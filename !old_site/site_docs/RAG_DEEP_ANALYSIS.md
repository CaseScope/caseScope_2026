# CaseScope RAG Deep Analysis: Why It's Returning Poor Results

## The Core Problem

When you ask **"Do you see signs of malware?"**, here's what happens:

```
Question: "Do you see signs of malware?"
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│ KEYWORD EXTRACTION                                               │
│ Extracted: ["malware", "signs"]                                  │
│                                                                  │
│ Problem: "malware" won't match:                                  │
│   - powershell.exe -encodedcommand (encoded commands)           │
│   - certutil -decode (LOLBin abuse)                             │
│   - schtasks /create (persistence)                               │
│   - net user /add (account creation)                            │
│   - reg add HKLM\...\Run (registry persistence)                 │
└─────────────────────────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│ FIELD SEARCH (only 9 fields!)                                    │
│                                                                  │
│ Currently searching:                                             │
│   - event_title, event_description  ← Good but limited          │
│   - computer_name, username         ← Won't match "malware"     │
│   - process_name, command_line      ← Might match if lucky      │
│   - source_ip, destination_ip       ← Won't match               │
│   - file_path                       ← Won't match               │
│                                                                  │
│ NOT searching:                                                   │
│   - search_blob ← THIS HAS ALL THE DATA!                        │
└─────────────────────────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│ RESULT: Returns events where "malware" appears literally         │
│                                                                  │
│ You get:                                                         │
│   - Defender logs with "malware" in description                 │
│   - Maybe some SIGMA rules with "malware" in title              │
│                                                                  │
│ You DON'T get:                                                   │
│   - Encoded PowerShell execution                                │
│   - Suspicious scheduled tasks                                  │
│   - Process injection events                                    │
│   - LOLBin abuse (certutil, mshta, regsvr32)                   │
│   - Persistence mechanisms                                      │
└─────────────────────────────────────────────────────────────────┘
```

---

## Issue #1: search_blob Not Being Searched

Your `search_blob` field contains ALL the event data flattened for search. But the multi_match query only searches 9 specific fields:

```python
# Current (MISSING search_blob!)
search_fields = [
    "event_title^3",
    "event_description^2",
    "computer_name",
    "username",
    "process_name",
    "command_line",
    "source_ip",
    "destination_ip",
    "file_path"
]
```

**Fix**: Add `search_blob` to the search fields.

---

## Issue #2: No Query Expansion for DFIR Concepts

When an analyst asks about "malware", they mean a CONCEPT, not a literal string. The system should expand this:

```
"malware" should expand to:
├── Suspicious executables: powershell, cmd, wscript, cscript, mshta, regsvr32
├── LOLBins: certutil, bitsadmin, msiexec, rundll32
├── Encoding indicators: -enc, -encodedcommand, base64, frombase64
├── Persistence: schtasks, at.exe, reg add, HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
├── Network indicators: invoke-webrequest, downloadstring, downloadfile, curl, wget
├── Process behaviors: createremotethread, virtualallocex, writeprocessmemory
└── Event IDs: 4688 (process), 7045 (service), 4698 (task), 1 (Sysmon process)
```

---

## Issue #3: High-Volume Events Dominate

4624/4625 (logon) events are extremely common. Any query with "user" or "account" returns hundreds of these.

**Current behavior**: Return top 100 by score → 80 are logon events → Semantic re-ranking still has 80 logon events in the pool.

**Needed behavior**: Diversify by event type to ensure variety.

---

## Issue #4: Embedding Model Doesn't Understand DFIR

`all-MiniLM-L6-v2` is trained on general text. In its embedding space:
- "lateral movement" is NOT close to "PsExec" or "WMI" 
- "credential theft" is NOT close to "LSASS" or "mimikatz"
- "malware" is NOT close to "powershell -encodedcommand"

The semantic similarity scores are essentially random noise for DFIR concepts.

---

## Issue #5: Event Summary Missing Critical Context

Current summary:
```
Time: 2025-11-24T14:32:05 | Computer: WS01 | Event ID: 4688
FLAGS: ⚠️ SIGMA HIGH
DATA: SubjectUserSid S-1-5-21... SubjectUserName SYSTEM ...
```

What the LLM actually needs:
```
Time: 2025-11-24T14:32:05 | Computer: WS01 | Event ID: 4688 (Process Created)
FLAGS: ⚠️ SIGMA HIGH - "Encoded PowerShell Command Line"
Process Chain: explorer.exe → cmd.exe → powershell.exe -encodedcommand JABz...
User: DOMAIN\admin
```

---

# THE SOLUTION: DFIR-Aware RAG

## 1. Query Expansion Dictionary

```python
# DFIR concept expansion - maps analyst questions to actual indicators
DFIR_QUERY_EXPANSION = {
    # Malware / Suspicious Activity
    'malware': [
        'powershell', 'encodedcommand', 'enc', 'base64', 'frombase64string',
        'invoke-expression', 'iex', 'downloadstring', 'downloadfile',
        'certutil', 'decode', 'urlcache', 'bitsadmin', 'mshta', 'wscript',
        'cscript', 'regsvr32', 'rundll32', 'msiexec', 'cmd.exe /c',
        'hidden', 'bypass', 'noprofile', 'windowstyle hidden',
        '4688', '4689', '1',  # Process events
    ],
    
    'lateral movement': [
        'psexec', 'paexec', 'remcom', 'wmic', 'wmiexec', 'smbexec',
        'winrm', 'winrs', 'enter-pssession', 'invoke-command',
        'rdp', 'mstsc', 'remote desktop', '3389',
        'net use', 'admin$', 'c$', 'ipc$',
        'pass the hash', 'pth', 'pass the ticket', 'ptt',
        'type 3 logon', 'type 10 logon', 'network logon',
        '4624', '4648', '5140', '5145',  # Relevant event IDs
    ],
    
    'persistence': [
        'schtasks', 'scheduled task', 'at.exe', 'task scheduler',
        'registry run', 'currentversion\\run', 'runonce',
        'services', 'new service', 'sc create', 'sc config',
        'startup folder', 'startup programs',
        'wmi subscription', 'wmi event', '__eventfilter',
        'dll hijack', 'com hijack',
        '4698', '4699', '4702', '7045', '4697',  # Task and service events
    ],
    
    'credential': [
        'lsass', 'mimikatz', 'sekurlsa', 'logonpasswords',
        'sam', 'system', 'security', 'ntds', 'ntds.dit',
        'dcsync', 'drsuapi', 'credential', 'password',
        'kerberos', 'tgt', 'krbtgt', 'golden ticket', 'silver ticket',
        'hashdump', 'pwdump', 'procdump', 'comsvcs',
        'minidump', 'memdump',
        '4768', '4769', '4776', '4672',  # Auth events
    ],
    
    'exfiltration': [
        'upload', 'exfil', 'transfer', 'send',
        'ftp', 'sftp', 'scp', 'curl', 'wget', 'invoke-webrequest',
        'cloud', 'onedrive', 'dropbox', 'gdrive', 'mega',
        'archive', 'zip', 'rar', '7z', 'compress',
        'dns tunnel', 'icmp tunnel',
        'large file', 'bulk', 'many files',
    ],
    
    'discovery': [
        'whoami', 'hostname', 'ipconfig', 'ifconfig', 'netstat',
        'net user', 'net group', 'net localgroup', 'net share',
        'nltest', 'dsquery', 'ldapsearch',
        'arp', 'route print', 'tracert', 'nslookup',
        'systeminfo', 'tasklist', 'wmic process', 'query user',
        'dir /s', 'tree', 'findstr', 'find /i',
    ],
    
    'defense evasion': [
        'disable', 'stop', 'tamper', 'defender',
        'amsi', 'etw', 'event log', 'clear-eventlog',
        'wevtutil', '1102',  # Audit log cleared
        'firewall', 'netsh', 'advfirewall',
        'uac bypass', 'elevation', 'runas',
        'process hollow', 'process inject', 'createremotethread',
    ],
}

# Map common question patterns to expansion categories
QUESTION_PATTERNS = {
    r'malware|virus|trojan|ransomware|infection|compromise': 'malware',
    r'lateral\s*movement|spread|pivot|move\s+to|hop': 'lateral movement', 
    r'persist|backdoor|maintain\s+access|survive\s+reboot': 'persistence',
    r'credential|password|hash|ticket|authentication|logon\s+as': 'credential',
    r'exfil|steal\s+data|data\s+theft|upload|send\s+out': 'exfiltration',
    r'recon|discover|enumerate|scan|map\s+network': 'discovery',
    r'evad|bypass|disable|hide|obfuscat': 'defense evasion',
}
```

## 2. Updated Search Function

```python
def expand_query_for_dfir(question: str) -> List[str]:
    """
    Expand a natural language question into DFIR-relevant search terms.
    """
    import re
    
    expanded_terms = []
    question_lower = question.lower()
    
    # Check which DFIR concepts the question maps to
    matched_categories = set()
    for pattern, category in QUESTION_PATTERNS.items():
        if re.search(pattern, question_lower):
            matched_categories.add(category)
    
    # Add expansion terms for matched categories
    for category in matched_categories:
        if category in DFIR_QUERY_EXPANSION:
            expanded_terms.extend(DFIR_QUERY_EXPANSION[category])
    
    # Also check for direct mentions of category names
    for category, terms in DFIR_QUERY_EXPANSION.items():
        if category in question_lower:
            expanded_terms.extend(terms)
    
    # Deduplicate while preserving some order
    seen = set()
    unique_terms = []
    for term in expanded_terms:
        if term not in seen:
            seen.add(term)
            unique_terms.append(term)
    
    return unique_terms[:30]  # Limit to top 30 expansion terms


def semantic_search_events_v2(
    opensearch_client,
    case_id: int,
    question: str,
    max_results: int = 20,
) -> Tuple[List[Dict], str]:
    """
    Improved semantic search with DFIR query expansion and diversification.
    """
    index_name = f"case_{case_id}"
    
    # Step 1: Extract keywords + DFIR expansion
    keywords = extract_keywords_from_question(question)
    dfir_terms = expand_query_for_dfir(question)
    
    # Combine: user keywords first, then expansions
    all_search_terms = keywords + [t for t in dfir_terms if t not in keywords]
    
    if not all_search_terms:
        return [], "Could not understand your question."
    
    logger.info(f"[AI_SEARCH] Keywords: {keywords[:10]}")
    logger.info(f"[AI_SEARCH] DFIR expansion: {dfir_terms[:15]}")
    
    # Step 2: Build diversified query
    should_clauses = []
    
    # CRITICAL: Search the search_blob field!
    search_fields = [
        "search_blob",           # THE MAIN DATA FIELD
        "event_title^3",
        "event_description^2", 
        "command_line^2",
        "process_name",
        "file_path",
    ]
    
    # Add user's keywords with high boost
    for keyword in keywords[:10]:
        should_clauses.append({
            "multi_match": {
                "query": keyword,
                "fields": search_fields,
                "type": "best_fields",
                "fuzziness": "AUTO",
                "boost": 3.0  # User terms are important
            }
        })
    
    # Add DFIR expansion terms with lower boost
    for term in dfir_terms[:20]:
        should_clauses.append({
            "multi_match": {
                "query": term,
                "fields": search_fields,
                "type": "phrase_prefix" if ' ' in term else "best_fields",
                "boost": 1.5
            }
        })
    
    # Boost flagged events
    should_clauses.extend([
        {"term": {"is_tagged": {"value": True, "boost": 10.0}}},
        {"term": {"has_sigma": {"value": True, "boost": 5.0}}},
        {"term": {"has_ioc": {"value": True, "boost": 4.0}}},
    ])
    
    query = {
        "bool": {
            "should": should_clauses,
            "minimum_should_match": 1
        }
    }
    
    # Step 3: Execute with aggregation for diversity
    response = opensearch_client.search(
        index=index_name,
        body={
            "query": query,
            "size": 0,  # We'll use aggregations
            "aggs": {
                "by_event_id": {
                    "terms": {
                        "field": "normalized_event_id",
                        "size": 50  # Get top 50 event types
                    },
                    "aggs": {
                        "top_events": {
                            "top_hits": {
                                "size": 3,  # Max 3 per event type
                                "_source": True,
                                "sort": [{"_score": {"order": "desc"}}]
                            }
                        }
                    }
                }
            },
            "timeout": "30s"
        }
    )
    
    # Step 4: Collect diversified results
    candidates = []
    for bucket in response['aggregations']['by_event_id']['buckets']:
        event_id = bucket['key']
        for hit in bucket['top_events']['hits']['hits']:
            event = {
                '_id': hit['_id'],
                '_index': hit['_index'],
                '_score': hit.get('_score', 0),
                '_source': hit['_source'],
                '_event_type': event_id
            }
            candidates.append(event)
    
    # Also get tagged events (they're stored in PostgreSQL)
    tagged_events = get_tagged_events_from_db(case_id, index_name)
    for te in tagged_events:
        if te['_id'] not in {c['_id'] for c in candidates}:
            te['_score'] = 100.0  # Ensure they rank high
            candidates.append(te)
    
    logger.info(f"[AI_SEARCH] Diversified results: {len(candidates)} events across {len(response['aggregations']['by_event_id']['buckets'])} event types")
    
    # Step 5: Semantic re-ranking (same as before but with better summaries)
    # ... existing re-ranking code ...
    
    return candidates[:max_results], f"Found {len(candidates)} diverse events"
```

## 3. Enhanced Event Summary with SIGMA Context

```python
def create_event_summary_v2(event: Dict[str, Any]) -> str:
    """
    Create DFIR-aware event summary with attack context.
    """
    source = event.get('_source', event)
    
    # Header with meaningful description
    timestamp = source.get('normalized_timestamp', 'Unknown time')
    computer = source.get('normalized_computer', 'Unknown')
    event_id = source.get('normalized_event_id', 'Unknown')
    event_title = source.get('event_title', '')
    
    header = f"**{timestamp}** | {computer} | Event {event_id}"
    if event_title:
        header += f" ({event_title})"
    
    parts = [header]
    
    # Detection context (this is GOLD for the LLM)
    if source.get('is_tagged'):
        parts.append("⭐ **ANALYST TAGGED** - Analyst marked this as significant")
    
    if source.get('has_sigma'):
        sigma_rules = source.get('sigma_rules', [])
        sigma_level = source.get('sigma_level', 'unknown').upper()
        if sigma_rules:
            rule_names = [r.get('title', r.get('name', '')) for r in sigma_rules[:3]]
            parts.append(f"⚠️ **SIGMA {sigma_level}**: {', '.join(rule_names)}")
        else:
            parts.append(f"⚠️ **SIGMA {sigma_level}** detection triggered")
    
    if source.get('has_ioc'):
        ioc_matches = source.get('ioc_matches', [])
        if ioc_matches:
            ioc_summary = ', '.join(str(m.get('value', ''))[:40] for m in ioc_matches[:2])
            parts.append(f"🎯 **IOC MATCH**: {ioc_summary}")
        else:
            parts.append(f"🎯 **IOC MATCH** ({source.get('ioc_count', 1)} indicators)")
    
    # Key forensic fields (structured, not blob)
    event_data = source.get('EventData', {}) or source.get('Event', {}).get('EventData', {})
    if isinstance(event_data, dict):
        # User context
        user = event_data.get('TargetUserName') or event_data.get('SubjectUserName') or event_data.get('User')
        if user:
            parts.append(f"User: {user}")
        
        # Process context (THE KEY FOR MALWARE DETECTION)
        process = event_data.get('NewProcessName') or event_data.get('Image') or event_data.get('ProcessName')
        parent = event_data.get('ParentProcessName') or event_data.get('ParentImage')
        if process:
            if parent:
                parts.append(f"Process: {parent} → {process}")
            else:
                parts.append(f"Process: {process}")
        
        # Command line (CRITICAL)
        cmdline = event_data.get('CommandLine') or event_data.get('command_line')
        if cmdline:
            # Show more - this is essential
            parts.append(f"CommandLine: {cmdline[:500]}")
        
        # Network
        src_ip = event_data.get('IpAddress') or event_data.get('SourceNetworkAddress')
        if src_ip and src_ip not in ['-', '::1', '127.0.0.1', '']:
            parts.append(f"Source IP: {src_ip}")
        
        # Target
        target = event_data.get('TargetFilename') or event_data.get('ObjectName') or event_data.get('ShareName')
        if target:
            parts.append(f"Target: {target[:200]}")
    
    # Fallback to search_blob excerpt if no structured data
    if len(parts) <= 2:
        blob = source.get('search_blob', '')
        if blob:
            parts.append(f"Data: {blob[:800]}")
    
    return '\n'.join(parts)
```

## 4. Improved LLM Prompt with Attack Context

```python
ENHANCED_PROMPT = """You are a senior Digital Forensics and Incident Response (DFIR) analyst. You're investigating a potential security incident and need to analyze the retrieved evidence.

## CASE: {case_name}

## ANALYST'S QUESTION
{question}

## IMPORTANT CONTEXT FOR YOUR ANALYSIS

**How to Interpret Flags:**
- ⭐ ANALYST TAGGED = The analyst manually marked this event as important during their investigation
- ⚠️ SIGMA = Matches a threat detection rule (rule name tells you what's suspicious)
- 🎯 IOC = Matches a known indicator of compromise (IP, hash, domain, etc.)

**Common Attack Patterns to Consider:**
- Initial Access: Phishing → malicious macro → PowerShell download
- Execution: Encoded PowerShell, WMI, scheduled tasks
- Persistence: Services, scheduled tasks, registry Run keys
- Credential Access: LSASS memory access, DCSync, Kerberoasting
- Lateral Movement: PsExec (4688 with PSEXESVC), WMI (4688 with WmiPrvSE), RDP (4624 type 10)
- Exfiltration: Unusual outbound, cloud storage access, large transfers

**Windows Event ID Quick Reference:**
- 4624: Successful logon (check LogonType: 2=interactive, 3=network, 10=RDP)
- 4625: Failed logon (brute force indicator)
- 4648: Explicit credential use (pass-the-hash indicator)
- 4672: Admin logon (privilege use)
- 4688: Process created (THE key event for execution)
- 4698/4699/4702: Scheduled task created/deleted/modified
- 7045: Service installed
- 1 (Sysmon): Process created with full command line

## EVIDENCE ({num_events} events)

{events_text}

## YOUR ANALYSIS TASK

1. **Answer the analyst's question** using ONLY the events above
2. **Reference events by number**: "[Event 3]" or "Event 3 shows..."
3. **Look for patterns**: Chain of events, not just individual events
4. **Pay attention to flags**: ⭐ tagged events are analyst-verified important
5. **Note what's missing**: If you can't fully answer, say what evidence you'd need
6. **Connect the timeline**: If events are related, explain the sequence

**DO NOT:**
- Make up information not in the events
- Assume things that aren't evidenced
- Ignore the SIGMA/IOC flags (they're there for a reason)

## YOUR ANALYSIS:
"""
```

---

# Summary of Changes Needed

| Issue | Current | Fixed |
|-------|---------|-------|
| Search fields | 9 specific fields | Add `search_blob` |
| Query expansion | None | DFIR concept mapping |
| Result diversity | Top N by score | Diversify by event type |
| Event summary | Raw data blob | Structured + SIGMA names |
| LLM prompt | Generic DFIR | Attack pattern context |
| 4624/4625 dominance | Returns 80% logon | Max 3 per event type |

## Quick Wins (30 minutes)

1. **Add search_blob to search_fields** - One line change
2. **Add event_title to summary** - Already have it, just display it
3. **Include SIGMA rule names** - Already in source, just extract

## Medium Effort (2-4 hours)

4. **Query expansion dictionary** - Map concepts to indicators
5. **Diversification via aggregation** - One query change
6. **Enhanced LLM prompt** - Paste in the improved version

## Advanced (1-2 days)

7. **Fine-tune embedding model on DFIR corpus** - Would help semantic similarity
8. **Pre-compute event embeddings** - Faster search on large cases
9. **Chain detection** - Find sequences of related events automatically
