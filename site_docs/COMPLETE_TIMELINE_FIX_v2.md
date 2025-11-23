# COMPLETE TIMELINE HALLUCINATION FIX
## Single Implementation Document with DFIR-Compliant Prompt

**Version**: 2.0  
**Date**: November 21, 2025  
**Purpose**: Fix AI timeline hallucination by using tagged events + proper DFIR report structure  

---

## TABLE OF CONTENTS

1. [Problem Summary](#problem-summary)
2. [Complete Solution Overview](#complete-solution-overview)
3. [PATCH 1: tasks.py - Use Tagged Events](#patch-1-taskspy)
4. [PATCH 2: ai_report.py - DFIR-Compliant Prompt](#patch-2-ai_reportpy)
5. [Implementation Steps](#implementation-steps)
6. [Testing Checklist](#testing-checklist)

---

## PROBLEM SUMMARY

**Current Issue**: AI timeline generation hallucinating events instead of using tagged events from CSV exports.

**Root Causes**:
1. ❌ Timeline fetches random 300 events from 8.7M total (ignoring TimelineTag table)
2. ❌ Prompt says "SAMPLE EVENTS" which tells AI data is incomplete
3. ❌ Prompt lacks proper DFIR structure (no evidence source, relevance, IOCs, root cause)
4. ❌ No chronological event list with proper timestamps

**Solution**:
1. ✅ Query TimelineTag table for analyst-tagged events
2. ✅ Load ALL tagged events (no 300 cap)
3. ✅ Use DFIR-compliant prompt structure
4. ✅ Include proper evidence sourcing and analysis sections

---

## COMPLETE SOLUTION OVERVIEW

```
BEFORE (BROKEN):
User Tags Events → TimelineTag Table (IGNORED)
                                     ↓
Timeline Generation → Query ALL 8.7M events
                                     ↓
Take Random 300 Sample → Incomplete Data
                                     ↓
Prompt: "SAMPLE EVENTS" → AI Fills Gaps
                                     ↓
AI HALLUCINATES Events ❌

AFTER (FIXED):
User Tags Events → TimelineTag Table
                                     ↓
Timeline Generation → Query TimelineTag
                                     ↓
Load ALL Tagged Events → Complete Dataset
                                     ↓
Prompt: "ANALYST-TAGGED EVENTS" → AI Uses Only Tagged
                                     ↓
DFIR-Compliant Timeline ✅
```

---

## PATCH 1: tasks.py

**File**: `/opt/casescope/app/tasks.py`  
**Function**: `generate_case_timeline()`  
**Lines**: ~1657-1715

### REMOVE THIS ENTIRE SECTION:

```python
# Get sample events from OpenSearch (for timeline context)
# We'll fetch events sorted by timestamp to establish chronological boundaries
timeline.progress_percent = 30
timeline.progress_message = 'Fetching events from OpenSearch...'
db.session.commit()

events_data = []
event_count = 0
try:
    # v1.13.1: Uses consolidated index (case_{id}, not per-file indices)
    index_pattern = f"case_{case.id}"
    
    # Get count first
    count_result = opensearch_client.count(
        index=index_pattern,
        body={"query": {"match_all": {}}},
        ignore_unavailable=True
    )
    event_count = count_result.get('count', 0) if count_result else 0
    logger.info(f"[TIMELINE] Total events in case: {event_count:,}")
    
    if event_count > 0:
        # Fetch sample events sorted by timestamp
        # v1.18.3 FIX: Use normalized fields for sorting and querying
        search_body = {
            "query": {"match_all": {}},
            "size": min(300, event_count),  # Cap at 300 events for timeline
            "sort": [{"normalized_timestamp": {"order": "asc", "unmapped_type": "date"}}],
            "_source": {
                "includes": [
                    "Event.System.TimeCreated",
                    "Event.System.Computer",
                    "Event.System.EventID",
                    "Event.EventData",
                    "normalized_timestamp",
                    "normalized_computer",
                    "normalized_event_id",
                    "source_file_type",
                    "has_ioc",
                    "has_sigma",
                    "sigma_rule"
                ]
            }
        }
        
        results = opensearch_client.search(
            index=index_pattern,
            body=search_body,
            ignore_unavailable=True
        )
        
        if results and 'hits' in results and 'hits' in results['hits']:
            events_data = results['hits']['hits']
            logger.info(f"[TIMELINE] Retrieved {len(events_data)} sample events for timeline")
            
except Exception as e:
    logger.warning(f"[TIMELINE] Error fetching events: {e}")
    # Continue without events
```

### REPLACE WITH THIS CODE:

```python
# ========================================================================
# STAGE 1B: Load TAGGED events (analyst-curated timeline events)
# ========================================================================
timeline.progress_percent = 30
timeline.progress_message = 'Fetching analyst-tagged events...'
db.session.commit()

from models import TimelineTag

# Query all tagged events for this case
tagged_events = TimelineTag.query.filter_by(case_id=case.id).order_by(TimelineTag.created_at).all()
logger.info(f"[TIMELINE] Found {len(tagged_events)} analyst-tagged events")

# Check if any events are tagged
if not tagged_events:
    logger.error(f"[TIMELINE] No tagged events found for case {case.id}")
    timeline.error_message = ("No events have been tagged for timeline generation. "
                             "Timeline generation requires analyst-tagged events. "
                             "Please tag relevant events in the search interface before generating a timeline.")
    timeline.status = 'failed'
    timeline.event_count = 0
    timeline.ioc_count = len(iocs)
    timeline.system_count = len(systems)
    db.session.commit()
    return {'status': 'error', 'message': 'No tagged events found. Please tag events first.'}

# Fetch full event data from OpenSearch for each tagged event
timeline.progress_percent = 40
timeline.progress_message = f'Loading full data for {len(tagged_events)} tagged events...'
db.session.commit()

events_data = []
event_count = len(tagged_events)  # Use TAGGED count, not total database count
failed_loads = 0
loaded_from_cache = 0

try:
    for idx, tag in enumerate(tagged_events):
        # Update progress every 50 events to avoid excessive DB writes
        if idx > 0 and idx % 50 == 0:
            progress = 40 + int((idx / len(tagged_events)) * 30)  # Progress from 40% to 70%
            timeline.progress_percent = min(progress, 70)
            timeline.progress_message = f'Loading event {idx}/{len(tagged_events)}...'
            db.session.commit()
            
            # Check for cancellation during event loading
            timeline = db.session.get(CaseTimeline, timeline_id)
            if timeline.status == 'cancelled':
                logger.info(f"[TIMELINE] Timeline {timeline_id} cancelled during event loading")
                return {'status': 'cancelled', 'message': 'Timeline generation was cancelled'}
        
        try:
            # Try to get full event from OpenSearch first
            event_doc = opensearch_client.get(
                index=tag.index_name,
                id=tag.event_id,
                ignore=[404]
            )
            
            if event_doc and event_doc.get('found'):
                # Successfully retrieved from OpenSearch
                events_data.append(event_doc)
                logger.debug(f"[TIMELINE] Loaded event {tag.event_id} from OpenSearch")
            else:
                # Event not found in OpenSearch, try cached data
                if tag.event_data:
                    import json as json_lib
                    try:
                        cached_event = json_lib.loads(tag.event_data)
                        events_data.append({
                            '_source': cached_event,
                            '_id': tag.event_id,
                            '_index': tag.index_name,
                            'from_cache': True,
                            'analyst_notes': tag.notes if tag.notes else None,
                            'tag_color': tag.tag_color
                        })
                        loaded_from_cache += 1
                        logger.debug(f"[TIMELINE] Using cached data for event {tag.event_id}")
                    except json_lib.JSONDecodeError as je:
                        logger.warning(f"[TIMELINE] Failed to parse cached data for {tag.event_id}: {je}")
                        failed_loads += 1
                else:
                    logger.warning(f"[TIMELINE] Event {tag.event_id} not found and no cached data available")
                    failed_loads += 1
        
        except Exception as e:
            logger.warning(f"[TIMELINE] Error fetching event {tag.event_id}: {e}")
            # Try cached data as fallback
            if tag.event_data:
                try:
                    import json as json_lib
                    cached_event = json_lib.loads(tag.event_data)
                    events_data.append({
                        '_source': cached_event,
                        '_id': tag.event_id,
                        '_index': tag.index_name,
                        'from_cache': True,
                        'analyst_notes': tag.notes if tag.notes else None,
                        'tag_color': tag.tag_color
                    })
                    loaded_from_cache += 1
                    logger.debug(f"[TIMELINE] Used cached data after fetch error for {tag.event_id}")
                except Exception as cache_err:
                    logger.warning(f"[TIMELINE] Could not use cached data for {tag.event_id}: {cache_err}")
                    failed_loads += 1
            else:
                failed_loads += 1

    logger.info(f"[TIMELINE] Loaded {len(events_data)}/{len(tagged_events)} events "
               f"({loaded_from_cache} from cache, {failed_loads} failed)")
    
    # Sort events by timestamp (chronological order)
    events_data.sort(key=lambda x: x.get('_source', {}).get('normalized_timestamp', ''))

except Exception as e:
    logger.error(f"[TIMELINE] Critical error loading tagged events: {e}")
    timeline.error_message = f"Error loading tagged events: {str(e)}"
    timeline.status = 'failed'
    timeline.event_count = 0
    timeline.ioc_count = len(iocs)
    timeline.system_count = len(systems)
    db.session.commit()
    return {'status': 'error', 'message': f'Error loading events: {str(e)}'}

# Verify we got at least some events
if not events_data:
    logger.error(f"[TIMELINE] No event data could be loaded for any tagged events")
    timeline.error_message = ("Could not load any tagged event data from OpenSearch. "
                             "Events may have been deleted or indices may be unavailable.")
    timeline.status = 'failed'
    timeline.event_count = 0
    timeline.ioc_count = len(iocs)
    timeline.system_count = len(systems)
    db.session.commit()
    return {'status': 'error', 'message': 'No event data available'}

# Warn if significant number of events failed to load
if failed_loads > 0:
    logger.warning(f"[TIMELINE] {failed_loads} events failed to load out of {len(tagged_events)} "
                  f"({failed_loads/len(tagged_events)*100:.1f}%)")
```

---

## PATCH 2: ai_report.py

**File**: `/opt/casescope/app/ai_report.py`  
**Function**: `generate_timeline_prompt()`  
**Lines**: ~215-406

### REPLACE THE ENTIRE FUNCTION WITH THIS DFIR-COMPLIANT VERSION:

```python
def generate_timeline_prompt(case, iocs, systems, events_data, event_count):
    """
    Build DFIR-compliant timeline prompt for AI generation (v2.0)
    
    This prompt follows DFIR best practices:
    - Chronological event list with precise timestamps
    - Evidence source for each event
    - Relevance/analysis context
    - Proper IOC tracking
    - Attack progression analysis
    - Root cause identification
    - Post-incident recommendations
    
    Args:
        case: Case object
        iocs: List of IOC objects
        systems: List of System objects
        events_data: List of TAGGED event dicts from analyst (sorted by timestamp)
        event_count: Number of tagged events (not total events)
        
    Returns:
        str: DFIR-compliant timeline prompt
    """
    
    # Count first/last event timestamps for summary
    first_event_time = "Unknown"
    last_event_time = "Unknown"
    if events_data:
        first_event_time = events_data[0].get('_source', {}).get('normalized_timestamp', 'Unknown')
        last_event_time = events_data[-1].get('_source', {}).get('normalized_timestamp', 'Unknown')
    
    prompt = f"""You are a DFIR Timeline Analysis Engine creating a professional forensic timeline report.

═══════════════════════════════════════════════════════════════════════════════
🎯 MISSION: CHRONOLOGICAL TIMELINE FROM ANALYST-TAGGED EVENTS
═══════════════════════════════════════════════════════════════════════════════

Create a precise chronological timeline from events the analyst has tagged as significant.

⚠️ CRITICAL: The analyst has pre-filtered events and explicitly tagged {event_count} events as timeline-relevant.
Every event below was manually selected by the analyst as important for understanding this case.
Your job is to organize these tagged events into a coherent DFIR timeline narrative.

═══════════════════════════════════════════════════════════════════════════════
📊 CASE INFORMATION
═══════════════════════════════════════════════════════════════════════════════

Case Name: {case.name}
Company: {case.company or 'Unknown'}
Description: {case.description or 'No description'}

EVENT SCOPE:
- Events Tagged for Timeline: {event_count}
- Active IOCs: {len(iocs)}
- Systems in Scope: {len(systems)}
- Timeline Span: {first_event_time} to {last_event_time}

═══════════════════════════════════════════════════════════════════════════════
📝 REQUIRED TIMELINE SECTIONS (DFIR Standard)
═══════════════════════════════════════════════════════════════════════════════

Your timeline report MUST include these sections in this order:

## Section 1: Timeline Summary
- First tagged event timestamp (UTC with timezone)
- Last tagged event timestamp (UTC with timezone)
- Total time span
- Total events analyzed: {event_count}
- Breakdown: Individual entries vs consolidated groups
- Key activity periods identified

## Section 2: Event Consolidation Summary
Create a table showing what was grouped:

| Category | Individual | Consolidated | Total |
|----------|-----------|--------------|-------|
| Logins   | ...       | ...          | ...   |
| Failed Logins | ... | ...          | ...   |
| Process Execution | ... | ...      | ...   |
| TOTAL    | ...       | ...          | {event_count} |

## Section 3: Chronological Timeline

### 3A. Individual Event Timeline (Ungrouped)
Show each event individually with this structure:

```
YYYY-MM-DD HH:MM:SS UTC | [SYSTEM-NAME] | Event Description
  ├─ Event ID: [EventID]
  ├─ Source File: [filename.evtx / filename.ndjson / etc]
  ├─ Evidence: [Specific log entry, artifact, or data source]
  ├─ IOC: [if IOC detected - show IOC type and value]
  ├─ SIGMA: [if SIGMA rule triggered - show rule name]
  ├─ Key Data: [User accounts, IP addresses, commands, file paths]
  └─ Relevance: [Why this event is significant, how it fits into attack progression]
```

### 3B. Consolidated Timeline (Grouped Events)
For better readability, group similar events within 10-minute windows:

```
YYYY-MM-DD HH:MM:SS to HH:MM:SS UTC | [MULTIPLE SYSTEMS] | Consolidated Event Description
  ├─ Event Type: [e.g., Failed Login Attempts, Process Executions]
  ├─ Event Details: EventID [X] - [Y] occurrences
  ├─ Key Data:
  │   ├─ Systems Affected: [System1, System2, System3] (N total)
  │   ├─ User Accounts: [user1, user2]
  │   ├─ Source IPs: [IP addresses]
  │   └─ Timespan: [duration in minutes/seconds]
  ├─ Evidence Source: [Source file types - EVTX, NDJSON, CSV, etc]
  └─ Context: [Attack technique, significance, correlation with other events]
```

## Section 4: Attack Progression Analysis

Break the timeline into attack phases:

### Phase 1: Reconnaissance (if applicable)
- Scanning activities
- Discovery commands
- Network enumeration

### Phase 2: Initial Access
- First successful authentication
- Initial compromise vector
- Entry point identification

### Phase 3: Execution
- Commands executed
- Scripts run
- Processes launched

### Phase 4: Persistence (if applicable)
- Scheduled tasks created
- Registry modifications
- Startup items added

### Phase 5: Privilege Escalation (if applicable)
- Elevation attempts
- Credential dumping
- Token manipulation

### Phase 6: Lateral Movement (if applicable)
- RDP connections
- SMB file shares accessed
- Network authentication events

### Phase 7: Exfiltration (if applicable)
- Large data transfers
- External connections
- Unusual network traffic

## Section 5: IOC Timeline Matrix

Show when each IOC was first/last seen:

| IOC Type | IOC Value | First Seen (UTC) | Last Seen (UTC) | Hit Count | Systems | Threat Level |
|----------|-----------|------------------|-----------------|-----------|---------|--------------|
| [type]   | [value]   | [timestamp]      | [timestamp]     | [count]   | [list]  | [level]      |

## Section 6: System Activity Timeline

Per-system summary showing activity windows:

| System Name | System Type | First Activity (UTC) | Last Activity (UTC) | Event Count | Notable Activity |
|-------------|-------------|---------------------|--------------------|-----------|--------------------|
| [name]      | [type]      | [timestamp]         | [timestamp]        | [count]   | [summary]          |

## Section 7: Initial Detection and Response
- How was the incident first detected?
- What triggered the investigation?
- Initial response actions taken

## Section 8: Incident Escalation
- When was the incident escalated?
- To whom was it escalated?
- Escalation criteria met

## Section 9: Attacker Activity Summary
- Tools used by attacker
- Techniques employed (MITRE ATT&CK TTPs if identifiable)
- Targets and objectives
- Dwell time

## Section 10: Root Cause Analysis
- How did the incident occur?
- What vulnerabilities were exploited?
- What controls failed?

## Section 11: Post-Incident Recommendations
- Immediate containment actions
- Security improvements needed
- Monitoring enhancements
- Policy/procedure updates
- Training requirements

═══════════════════════════════════════════════════════════════════════════════
🔍 INDICATORS OF COMPROMISE (IOCs)
═══════════════════════════════════════════════════════════════════════════════

"""
    
    if iocs:
        prompt += "Active IOCs to track in timeline:\n\n"
        for ioc in iocs:
            prompt += f"- **{ioc.ioc_type}**: `{ioc.ioc_value}`"
            if ioc.description:
                prompt += f" - {ioc.description}"
            if ioc.threat_level:
                prompt += f" [Threat Level: {ioc.threat_level}]"
            prompt += "\n"
    else:
        prompt += "⚠️ No IOCs defined for this case. Extract potential IOCs from events.\n"
    
    prompt += "\n═══════════════════════════════════════════════════════════════════════════════\n"
    prompt += "💻 SYSTEMS IN SCOPE\n"
    prompt += "═══════════════════════════════════════════════════════════════════════════════\n\n"
    
    if systems:
        for system in systems:
            prompt += f"- **{system.system_name}** ({system.system_type})"
            if system.ip_address:
                prompt += f" - IP: {system.ip_address}"
            prompt += "\n"
    else:
        prompt += "⚠️ No systems explicitly defined. Extract system names from events.\n"
    
    prompt += "\n═══════════════════════════════════════════════════════════════════════════════\n"
    prompt += f"📋 ANALYST-TAGGED EVENTS (ALL {len(events_data)} EVENTS BELOW)\n"
    prompt += "═══════════════════════════════════════════════════════════════════════════════\n\n"
    prompt += f"""⚠️ CRITICAL CONTEXT:
The analyst has tagged these {len(events_data)} events as timeline-relevant.
Each event below is significant and should be included in your timeline.
Do NOT invent or assume events that are not explicitly listed below.
Do NOT skip any events - all {len(events_data)} must be accounted for.\n\n"""
    
    if events_data:
        for idx, event_wrapper in enumerate(events_data, 1):  # NO CAP - Include ALL tagged events
            event = event_wrapper.get('_source', {})
            
            # Extract event details using normalized fields
            timestamp = event.get('normalized_timestamp', 'Unknown')
            computer = event.get('normalized_computer', 'Unknown')
            event_id = event.get('normalized_event_id', 'N/A')
            source_file = event.get('source_file', 'Unknown')
            source_type = event.get('source_file_type', 'Unknown')
            has_ioc = event.get('has_ioc', False)
            has_sigma = event.get('has_sigma', False)
            
            # Check for analyst notes from tagging
            analyst_notes = event_wrapper.get('analyst_notes', None)
            tag_color = event_wrapper.get('tag_color', None)
            from_cache = event_wrapper.get('from_cache', False)
            
            prompt += f"[{idx}] {timestamp} | {computer} | EventID:{event_id} ({source_type})"
            
            if has_ioc:
                matched_iocs = event.get('matched_iocs', [])
                prompt += f" 🎯IOC"
                if matched_iocs:
                    prompt += f":{','.join(matched_iocs[:2])}"  # Show first 2 IOCs
            
            if has_sigma:
                sigma_rules = event.get('sigma_rule', '')
                prompt += f" ⚠️SIGMA:{sigma_rules[:50]}"
            
            # Add event data context
            event_obj = event.get('Event', {})
            event_data_str = event_obj.get('EventData', '')
            user_data_str = event_obj.get('UserData', '')
            
            # Try to parse EventData
            event_data = {}
            if event_data_str and isinstance(event_data_str, str):
                try:
                    import json
                    event_data = json.loads(event_data_str)
                except:
                    pass
            elif isinstance(event_data_str, dict):
                event_data = event_data_str
            
            # If no EventData, try UserData (for some event types)
            if not event_data and user_data_str:
                if isinstance(user_data_str, str):
                    try:
                        import json
                        event_data = json.loads(user_data_str)
                    except:
                        pass
                elif isinstance(user_data_str, dict):
                    event_data = user_data_str
            
            # For NDJSON/EDR events, check top-level fields
            if not event_data:
                # Check for common EDR fields
                if 'process' in event:
                    event_data = event.get('process', {})
                elif 'CommandLine' in event or 'command_line' in event:
                    event_data = {
                        'CommandLine': event.get('CommandLine') or event.get('command_line'),
                        'Image': event.get('Image') or event.get('executable'),
                        'User': event.get('User') or event.get('user', {}).get('name')
                    }
            
            if event_data:
                # Show key fields
                key_fields = [
                    'TargetUserName', 'SubjectUserName', 'IpAddress', 'WorkstationName', 
                    'CommandLine', 'command_line', 'Image', 'TargetFilename', 'User',
                    'DestinationIp', 'DestinationPort', 'SourceIp', 'ProcessName'
                ]
                data_parts = []
                for field in key_fields:
                    value = event_data.get(field)
                    if value and value != '-' and value != '':
                        # Truncate long values
                        if isinstance(value, str) and len(value) > 100:
                            value = value[:97] + '...'
                        data_parts.append(f"{field}={value}")
                
                if data_parts:
                    prompt += f" | {', '.join(data_parts[:3])}"  # Show first 3 fields
            
            # Add source file for evidence tracking
            prompt += f"\n  └─ Source: {source_file}"
            
            # Add analyst notes if present
            if analyst_notes:
                prompt += f"\n  └─ Analyst Notes: {analyst_notes}"
            
            prompt += "\n"
    else:
        prompt += "❌ ERROR: No events available for timeline analysis.\n"
    
    prompt += "\n═══════════════════════════════════════════════════════════════════════════════\n"
    prompt += "⚙️ ANALYSIS INSTRUCTIONS - EVENT CONSOLIDATION RULES\n"
    prompt += "═══════════════════════════════════════════════════════════════════════════════\n\n"
    
    prompt += f"""
🔴 CRITICAL CONTEXT:

You are analyzing {len(events_data)} events that were MANUALLY TAGGED by the analyst.
Every event above is significant - the analyst has already filtered out noise.
Your task is to organize these events into a readable timeline narrative.

═══════════════════════════════════════════════════════════════════════════════
EVENT GROUPING RULES (OPTIONAL - For Readability)
═══════════════════════════════════════════════════════════════════════════════

You MAY group similar events within a **10-minute window** to improve readability:

**When to Group:**
✅ Multiple Logins (4624) → "Lateral movement: User X to N systems"
✅ Failed Logins (4625) → "Brute force: N failed attempts on [system]"
✅ Process Executions (4688) → "Command execution: [cmd] on N systems"
✅ File Access (4663) → "File access: N files in [share]"
✅ Network Connections (Sysmon 3) → "Network: N connections to [destination]"
✅ Registry Changes (Sysmon 12) → "Registry: N changes to [key path]"

**When Consolidating, You MUST:**
✅ Count total occurrences: "50 occurrences"
✅ Show time range: "11:00:15 to 11:05:43 UTC"  
✅ List affected systems: "Systems: SRV01, SRV02, WKS01-WKS12 (15 total)"
✅ Preserve IOC/SIGMA flags
✅ Include key data (users, IPs, commands, file paths)
✅ Reference source files for evidence tracking

**Example of Good Consolidation:**

```
2025-09-05 11:00:15 to 11:05:43 UTC | Multiple Systems
├─ Lateral Movement: User 'DOMAIN\\admin' authenticated to 15 systems
├─ Event Details: EventID 4624 Type 3 (Network Logon) - 50 occurrences
├─ Key Data:
│   ├─ User: DOMAIN\\admin
│   ├─ Systems: SRV01, SRV02, SRV03, WKS01-WKS12 (15 total)
│   ├─ Source IP: 192.168.1.100
│   └─ Timespan: 5 minutes 28 seconds
├─ Evidence Source: DC01_Security.evtx, SRV01_Security.evtx, [+13 files]
└─ Relevance: Rapid authentication pattern suggests lateral movement after initial compromise
```

**When NOT to Group (8 Exceptions):**
❌ Events with different IOC hits
❌ Events with different SIGMA violations
❌ Events with analyst notes (show individually)
❌ Events separated by >10 minutes
❌ Events in different attack phases
❌ Privilege escalation events (always show individually)
❌ Different commands (even if same EventID)
❌ Unique or rare events

═══════════════════════════════════════════════════════════════════════════════
DATA PRESERVATION GUARANTEE
═══════════════════════════════════════════════════════════════════════════════

🚨 CRITICAL REQUIREMENT:

All {len(events_data)} events MUST be accounted for in your timeline.

When you consolidate events:
✅ Count total occurrences: "50 occurrences"
✅ Show time range: "11:00:15 to 11:05:43 UTC"
✅ List affected systems: "15 systems: [list]"
✅ Preserve IOC/SIGMA flags
✅ Include key data (users, IPs, commands)
✅ Reference source files for evidence chain

**Verification**: Your Timeline Summary must show:
- Total events analyzed: {len(events_data)}
- Events shown individually: [your count]
- Events shown in consolidated groups: [your count]
- Sum of individual + grouped events MUST equal {len(events_data)}

═══════════════════════════════════════════════════════════════════════════════
FORMATTING RULES
═══════════════════════════════════════════════════════════════════════════════

**Timestamps:**
- Use UTC timezone exclusively (YYYY-MM-DD HH:MM:SS UTC)
- Always include timezone designation
- For grouped events, show time range with start and end times

**Evidence and Source:**
- Always cite source file for each event (filename.evtx, system_name.ndjson, etc.)
- For grouped events, reference multiple source files if applicable
- Maintain evidence chain integrity

**Relevance/Analysis:**
- Explain why each event/group is significant
- Show how it fits into the attack progression
- Connect events to IOCs and SIGMA detections
- Identify patterns (brute force, lateral movement, reconnaissance, etc.)

**Markdown Formatting:**
- Use tables for IOC matrix and system activity summary
- Use tree structure (├─ └─) for event details
- Bold system names, IOC values, and user accounts
- Keep descriptions concise but complete

**DO NOT:**
❌ Invent events or timestamps not in the list above
❌ Make assumptions about events between tagged events  
❌ Skip any of the {len(events_data)} tagged events
❌ Summarize without showing specific timestamps and evidence sources
❌ Create fake analyst notes or recommendations without basis in events

═══════════════════════════════════════════════════════════════════════════════
DFIR BEST PRACTICES
═══════════════════════════════════════════════════════════════════════════════

1. **Chronological Integrity**: Maintain strict chronological order
2. **Evidence Chain**: Always reference source files and artifacts
3. **IOC Tracking**: Track first/last seen for each IOC across systems
4. **Attack Phase Mapping**: Map events to MITRE ATT&CK or kill chain phases where applicable
5. **System Relationships**: Show how systems interact (authentication flows, file shares, network connections)
6. **Timeline Gaps**: Note significant gaps in activity (>4 hours) and explain possible reasons
7. **Suspicious Patterns**: Highlight anomalies, brute force, reconnaissance, lateral movement
8. **Root Cause Focus**: Work backwards from indicators to identify initial compromise vector
9. **Actionable Recommendations**: Base recommendations on actual findings, not generic advice

═══════════════════════════════════════════════════════════════════════════════
OUTPUT REQUIREMENTS
═══════════════════════════════════════════════════════════════════════════════

**Your timeline report must:**
1. Include ALL 11 required sections listed above
2. Account for all {len(events_data)} tagged events
3. Use proper DFIR formatting with timestamps, evidence sources, and relevance
4. Provide actionable insights based on the events
5. Be formatted in clean Markdown ready for display
6. Maintain professional forensic analysis tone

**Timeline Summary must include:**
- Total events analyzed: {len(events_data)}
- Events shown individually: [count]
- Events shown in consolidated groups: [count]  
- Verification: Individual + Grouped = {len(events_data)}
- Time span: {first_event_time} to {last_event_time}

Remember: Consolidation makes the timeline READABLE, not shorter.
All {len(events_data)} events must be accounted for, just organized intelligently.

Begin your analysis now.
"""
    
    return prompt
```

---

## IMPLEMENTATION STEPS

### Step 1: Backup Current Files (5 minutes)

```bash
# SSH to your CaseScope server
cd /opt/casescope/app

# Create backup directory
sudo mkdir -p /opt/casescope/backups/$(date +%Y%m%d_%H%M%S)

# Backup files
sudo cp tasks.py /opt/casescope/backups/$(date +%Y%m%d_%H%M%S)/tasks.py.backup
sudo cp ai_report.py /opt/casescope/backups/$(date +%Y%m%d_%H%M%S)/ai_report.py.backup

# Verify backups
ls -lh /opt/casescope/backups/$(date +%Y%m%d_%H%M%S)/
```

### Step 2: Apply PATCH 1 - tasks.py (10 minutes)

```bash
# Open tasks.py for editing
sudo nano /opt/casescope/app/tasks.py

# Find the section starting at line ~1657:
# "Get sample events from OpenSearch (for timeline context)"

# Delete lines 1657-1715 (the entire "Get sample events" section)

# Paste in the PATCH 1 code from above

# Save and exit (Ctrl+X, Y, Enter)

# Verify syntax
cd /opt/casescope/app
python3 -m py_compile tasks.py
# If no errors, syntax is valid
```

### Step 3: Apply PATCH 2 - ai_report.py (10 minutes)

```bash
# Open ai_report.py for editing
sudo nano /opt/casescope/app/ai_report.py

# Find function generate_timeline_prompt() starting at line ~215

# Select and delete the ENTIRE function (lines 215-406)

# Paste in the complete PATCH 2 function from above

# Save and exit (Ctrl+X, Y, Enter)

# Verify syntax
cd /opt/casescope/app
python3 -m py_compile ai_report.py
# If no errors, syntax is valid
```

### Step 4: Restart Services (5 minutes)

```bash
# Restart Celery workers (to pick up code changes)
sudo systemctl restart celery-casescope

# Verify Celery is running
sudo systemctl status celery-casescope

# Restart Gunicorn (optional, but recommended)
sudo systemctl restart gunicorn-casescope

# Verify Gunicorn is running
sudo systemctl status gunicorn-casescope

# Check logs for errors
sudo journalctl -u celery-casescope -f
# Press Ctrl+C to exit log view
```

### Step 5: Test with Small Case (15 minutes)

```bash
# 1. Log into CaseScope web interface
# 2. Open a test case with events
# 3. Tag 20-30 events using the search interface:
#    - Search for events with IOCs or SIGMA hits
#    - Click the tag icon on relevant events
#    - Verify tags are saved
#
# 4. Generate timeline:
#    - Click "Generate Timeline" button
#    - Monitor progress (should show "Loading tagged events...")
#    - Wait for completion (3-5 minutes)
#
# 5. Verify timeline:
#    - Check that all 20-30 tagged events appear
#    - Verify no hallucinated events
#    - Check that Timeline Summary shows correct event count
#    - Verify all 11 DFIR sections are present
#    - Check evidence sources are cited
#    - Confirm no events were skipped
```

---

## TESTING CHECKLIST

### Pre-Flight Checks
- [ ] Backup files created successfully
- [ ] Code syntax is valid (no Python errors)
- [ ] Celery service restarted and running
- [ ] Gunicorn service restarted and running

### Functional Testing
- [ ] Can tag events from search interface
- [ ] Timeline generation button works
- [ ] Progress updates show "Loading tagged events..."
- [ ] Generation completes without errors

### Timeline Quality Checks
- [ ] All tagged events appear in timeline (count matches)
- [ ] No hallucinated events (events not in tagged list)
- [ ] Timeline Summary section shows correct counts
- [ ] Event Consolidation Summary table is present
- [ ] Chronological Timeline includes all events
- [ ] Attack Progression Analysis is present
- [ ] IOC Timeline Matrix shows all IOCs
- [ ] System Activity Timeline lists all systems
- [ ] Initial Detection section is present
- [ ] Incident Escalation section is present
- [ ] Root Cause Analysis section is present
- [ ] Post-Incident Recommendations section is present

### Evidence Integrity
- [ ] Each event cites source file (e.g., Security.evtx)
- [ ] Timestamps include timezone (UTC)
- [ ] IOC hits are properly flagged
- [ ] SIGMA detections are properly flagged
- [ ] Analyst notes (if any) appear with events

### Data Preservation
- [ ] Timeline Summary shows: Individual + Consolidated = Total
- [ ] No events missing from timeline
- [ ] Consolidated groups show occurrence counts
- [ ] Consolidated groups show time ranges
- [ ] Consolidated groups list affected systems

### DFIR Compliance
- [ ] All 11 required sections present
- [ ] Professional forensic tone maintained
- [ ] Evidence sources properly cited
- [ ] Relevance/analysis provided for events
- [ ] Attack phases properly identified
- [ ] Recommendations based on actual findings

---

## ROLLBACK PROCEDURE (If Issues Occur)

```bash
# If you encounter issues, restore backups:

# Find your backup directory
ls -lh /opt/casescope/backups/

# Restore files (replace TIMESTAMP with your backup timestamp)
sudo cp /opt/casescope/backups/TIMESTAMP/tasks.py.backup /opt/casescope/app/tasks.py
sudo cp /opt/casescope/backups/TIMESTAMP/ai_report.py.backup /opt/casescope/app/ai_report.py

# Restart services
sudo systemctl restart celery-casescope
sudo systemctl restart gunicorn-casescope

# Verify services are running
sudo systemctl status celery-casescope
sudo systemctl status gunicorn-casescope
```

---

## TROUBLESHOOTING

### Issue: "No tagged events found"
**Solution**: Tag events in the search interface before generating timeline. The new code requires tagged events.

### Issue: Timeline generation fails with error
**Check logs**:
```bash
sudo journalctl -u celery-casescope -n 100
```
Look for errors related to TimelineTag or OpenSearch queries.

### Issue: Some events missing from timeline
**Verify**:
1. Events are actually tagged (check TimelineTag table in database)
2. OpenSearch indices are available
3. Check Celery logs for "failed to load" warnings

### Issue: Syntax errors after patching
**Solution**:
1. Verify you copied the complete code blocks
2. Check for indentation issues (Python is whitespace-sensitive)
3. Restore from backup and try again

---

## SUCCESS METRICS

**Before Fix:**
- ❌ Random 300 events from millions
- ❌ "SAMPLE EVENTS" prompt
- ❌ AI hallucination common
- ❌ Missing DFIR sections
- ❌ No evidence sourcing
- ❌ Analysts can't trust output

**After Fix:**
- ✅ Exactly N analyst-tagged events (whatever analyst tagged)
- ✅ "ANALYST-TAGGED EVENTS" prompt
- ✅ No hallucination (AI uses only tagged events)
- ✅ All 11 DFIR sections present
- ✅ Proper evidence sourcing for each event
- ✅ Analysts can trust and use timeline

---

## ADDITIONAL RECOMMENDATIONS

### 1. Add Tag Counter to UI

Show users how many events are tagged before timeline generation:

**File**: `/opt/casescope/app/templates/view_case.html` or similar

```html
<div class="alert alert-info">
    <i class="fas fa-tags"></i>
    <strong>{{ tagged_event_count }}</strong> events tagged for timeline
    {% if tagged_event_count == 0 %}
        <br><small class="text-warning">⚠️ Tag events before generating timeline</small>
    {% elif tagged_event_count < 20 %}
        <br><small>Consider tagging more events for comprehensive timeline</small>
    {% else %}
        <br><small>✓ Ready for timeline generation</small>
    {% endif %}
</div>
```

### 2. Add Bulk Tagging Feature

Allow analysts to tag multiple events at once from search results:

```javascript
// Add checkbox column to search results table
// Add "Tag Selected" button that calls bulk tag API endpoint
```

### 3. Add Timeline Preview

Before full generation, show a preview of what will be analyzed:

```
Timeline Preview:
✓ 450 tagged events
✓ Spanning: 2025-09-05 06:04:34 UTC to 2025-09-05 18:45:12 UTC  
✓ 15 systems involved
✓ 12 IOCs to track
✓ 8 SIGMA detections
⏱ Estimated time: 3-5 minutes

[Cancel] [Generate Timeline]
```

### 4. Export Tagged Events

Add route to export tagged events as CSV for external tools.

---

## CONCLUSION

This implementation fixes the AI timeline hallucination issue by:

1. ✅ **Using TimelineTag table** instead of random samples
2. ✅ **Loading ALL tagged events** (no 300 cap)
3. ✅ **DFIR-compliant prompt** with proper structure
4. ✅ **Evidence sourcing** for each event
5. ✅ **Professional forensic output** with all required sections

The timeline will now contain ONLY analyst-tagged events, properly formatted with evidence sources, relevance analysis, and actionable recommendations following DFIR best practices.

---

**Document Version**: 2.0 - Complete Implementation  
**Date**: November 21, 2025  
**Status**: Ready for Production Deployment  
**Estimated Implementation Time**: 45 minutes  
**Tested**: No (requires deployment and testing)
