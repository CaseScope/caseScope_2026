# CaseScope RAG Improvement Recommendations

## 1. Fixed Event Weighting Strategy

### Current (Problematic):
```python
combined_scores = 0.4 * os_scores_norm + 0.6 * similarities
```

### Recommended: Multi-Factor Scoring with Preserved Analyst Judgment

```python
def calculate_event_relevance(event: Dict, semantic_sim: float, os_score_norm: float) -> float:
    """
    Calculate event relevance with proper weighting.
    
    Weights:
    - Analyst Tagged: MUST be in top results (multiplicative boost, not additive)
    - IOC Match: Strong signal, but question-dependent
    - SIGMA Match: Important for threat detection questions
    - Semantic Similarity: Important for natural language questions
    - Keyword Match (OpenSearch): Important for specific terms
    """
    source = event.get('_source', {})
    
    # Base score from semantic + keyword
    base_score = 0.5 * os_score_norm + 0.5 * semantic_sim
    
    # Multiplicative boosts (don't get normalized away)
    boost = 1.0
    
    # Analyst-tagged events get MAJOR boost - analyst judgment matters
    if source.get('is_tagged'):
        boost *= 2.5  # Tagged events effectively double+ their score
    
    # IOC matches are strong signals
    if source.get('has_ioc'):
        ioc_count = source.get('ioc_count', 1)
        boost *= (1.0 + 0.3 * min(ioc_count, 5))  # 1.3x to 2.5x based on IOC count
    
    # SIGMA matches indicate suspicious activity
    if source.get('has_sigma'):
        sigma_level = source.get('sigma_level', 'medium')
        sigma_boosts = {'critical': 1.8, 'high': 1.5, 'medium': 1.3, 'low': 1.1}
        boost *= sigma_boosts.get(sigma_level, 1.2)
    
    return base_score * boost


def semantic_search_events_improved(
    opensearch_client,
    case_id: int,
    question: str,
    max_results: int = 20
) -> Tuple[List[Dict], str]:
    """
    Improved semantic search with better weighting.
    """
    # ... keyword extraction and OpenSearch query same as before ...
    
    # Re-ranking with proper weighting
    if embedding_available and len(candidates) > 1:
        question_embedding = get_embedding(question)
        event_summaries = [create_event_summary_enhanced(e) for e in candidates]
        event_embeddings = get_embeddings_batch(event_summaries)
        
        similarities = cosine_similarity_batch(question_embedding, event_embeddings)
        os_scores = np.array([e['_score'] for e in candidates])
        os_scores_norm = os_scores / (os_scores.max() + 0.001)
        
        # Calculate multi-factor scores
        combined_scores = np.array([
            calculate_event_relevance(candidates[i], similarities[i], os_scores_norm[i])
            for i in range(len(candidates))
        ])
        
        ranked_indices = np.argsort(combined_scores)[::-1]
        candidates = [candidates[i] for i in ranked_indices]
    
    return candidates[:max_results], explanation
```

---

## 2. Enhanced Event Summary for LLM Context

### Current (Minimal):
```python
"Time: 2025-11-24T14:32:05 | Computer: WS01 | Event ID: 4688 | CommandLine: powershell.exe"
```

### Recommended (Rich Context):

```python
# Windows Event ID descriptions for LLM context
EVENT_ID_DESCRIPTIONS = {
    # Authentication
    4624: "Successful logon",
    4625: "Failed logon attempt",
    4648: "Explicit credential logon (RunAs)",
    4672: "Special privileges assigned (admin logon)",
    4768: "Kerberos TGT requested",
    4769: "Kerberos service ticket requested",
    4776: "NTLM authentication attempt",
    
    # Process
    4688: "Process created",
    4689: "Process terminated",
    
    # Services & Tasks
    7045: "Service installed",
    4697: "Service installed (Security log)",
    4698: "Scheduled task created",
    4699: "Scheduled task deleted",
    4702: "Scheduled task updated",
    
    # Object Access
    4663: "Object access attempt",
    4656: "Handle to object requested",
    5140: "Network share accessed",
    5145: "Network share object checked",
    
    # System
    1102: "Audit log cleared",
    4616: "System time changed",
    
    # PowerShell
    4103: "PowerShell module logging",
    4104: "PowerShell script block logging",
    
    # Sysmon
    1: "Process created (Sysmon)",
    3: "Network connection (Sysmon)",
    7: "Image loaded (Sysmon)",
    8: "CreateRemoteThread (Sysmon)",
    10: "Process accessed (Sysmon)",
    11: "File created (Sysmon)",
    13: "Registry value set (Sysmon)",
    22: "DNS query (Sysmon)",
}

LOGON_TYPES = {
    2: "Interactive (local keyboard)",
    3: "Network (SMB, mapped drives)",
    4: "Batch (scheduled task)",
    5: "Service",
    7: "Unlock",
    8: "NetworkCleartext",
    9: "NewCredentials (RunAs /netonly)",
    10: "RemoteInteractive (RDP)",
    11: "CachedInteractive",
}


def create_event_summary_enhanced(event: Dict[str, Any]) -> str:
    """
    Create a rich, DFIR-aware event summary for LLM context.
    """
    source = event.get('_source', event)
    parts = []
    
    # Timestamp with relative context
    timestamp = source.get('normalized_timestamp') or source.get('@timestamp', 'Unknown')
    parts.append(f"**Time**: {timestamp}")
    
    # Computer
    computer = source.get('normalized_computer') or source.get('Computer', 'Unknown')
    parts.append(f"**Computer**: {computer}")
    
    # Event ID with description
    event_id = source.get('normalized_event_id') or source.get('EventID')
    if event_id:
        event_id = int(event_id) if str(event_id).isdigit() else event_id
        description = EVENT_ID_DESCRIPTIONS.get(event_id, "")
        if description:
            parts.append(f"**Event ID**: {event_id} ({description})")
        else:
            parts.append(f"**Event ID**: {event_id}")
    
    # EventData fields with context
    event_data = source.get('EventData', {})
    if isinstance(event_data, dict):
        
        # User context
        subject_user = event_data.get('SubjectUserName')
        target_user = event_data.get('TargetUserName')
        if subject_user and target_user and subject_user != target_user:
            parts.append(f"**User**: {subject_user} → {target_user}")
        elif target_user:
            parts.append(f"**User**: {target_user}")
        elif subject_user:
            parts.append(f"**User**: {subject_user}")
        
        # Logon type with description
        logon_type = event_data.get('LogonType')
        if logon_type:
            logon_type = int(logon_type) if str(logon_type).isdigit() else logon_type
            logon_desc = LOGON_TYPES.get(logon_type, "")
            if logon_desc:
                parts.append(f"**Logon Type**: {logon_type} ({logon_desc})")
        
        # Network info
        source_ip = event_data.get('IpAddress') or event_data.get('SourceNetworkAddress')
        if source_ip and source_ip != '-' and source_ip != '::1' and source_ip != '127.0.0.1':
            parts.append(f"**Source IP**: {source_ip}")
        
        # Process info with parent context
        process_name = event_data.get('NewProcessName') or event_data.get('Image')
        parent_process = event_data.get('ParentProcessName') or event_data.get('ParentImage')
        if process_name:
            if parent_process:
                parts.append(f"**Process**: {parent_process} → {process_name}")
            else:
                parts.append(f"**Process**: {process_name}")
        
        # Command line (critical for threat detection)
        cmdline = event_data.get('CommandLine') or event_data.get('command_line')
        if cmdline:
            # Truncate but preserve important parts
            cmdline_trunc = cmdline[:300] + "..." if len(cmdline) > 300 else cmdline
            parts.append(f"**Command Line**: {cmdline_trunc}")
        
        # File/Object access
        target_filename = event_data.get('TargetFilename') or event_data.get('ObjectName')
        if target_filename:
            parts.append(f"**Target**: {target_filename[:200]}")
        
        # Service info
        service_name = event_data.get('ServiceName')
        if service_name:
            parts.append(f"**Service**: {service_name}")
        
        # Task info  
        task_name = event_data.get('TaskName')
        if task_name:
            parts.append(f"**Task**: {task_name}")
        
        # Failure info
        status = event_data.get('Status')
        failure_reason = event_data.get('FailureReason')
        if failure_reason:
            parts.append(f"**Failure**: {failure_reason}")
        elif status and status != '0x0':
            parts.append(f"**Status**: {status}")
    
    # Detection flags with details
    flags = []
    if source.get('is_tagged'):
        flags.append("⭐ ANALYST TAGGED")
    
    if source.get('has_sigma'):
        sigma_rules = source.get('sigma_rules', [])
        if sigma_rules:
            rule_names = [r.get('title', r.get('name', 'Unknown')) for r in sigma_rules[:3]]
            flags.append(f"⚠️ SIGMA: {', '.join(rule_names)}")
        else:
            flags.append("⚠️ SIGMA VIOLATION")
    
    if source.get('has_ioc'):
        ioc_matches = source.get('ioc_matches', [])
        if ioc_matches:
            ioc_values = [str(m.get('value', ''))[:30] for m in ioc_matches[:3]]
            flags.append(f"🎯 IOC: {', '.join(ioc_values)}")
        else:
            flags.append(f"🎯 IOC MATCH ({source.get('ioc_count', 1)} indicators)")
    
    if flags:
        parts.append(f"**Flags**: {' | '.join(flags)}")
    
    return "\n".join(parts)
```

---

## 3. Improved LLM Prompt with DFIR Context

```python
def generate_ai_answer_improved(
    question: str,
    events: List[Dict],
    case_name: str,
    model: str = DEFAULT_LLM_MODEL,
    stream: bool = True
) -> Generator[str, None, None]:
    """
    Generate AI answer with enhanced DFIR-aware prompting.
    """
    # Build context from events
    event_context = []
    for i, event in enumerate(events[:15], 1):
        summary = create_event_summary_enhanced(event)
        event_id = event.get('_id', f'event_{i}')
        event_context.append(f"### Event {i}\n{summary}")
    
    events_text = "\n\n".join(event_context)
    
    # Count what we have for context
    tagged_count = sum(1 for e in events if e.get('_source', {}).get('is_tagged'))
    sigma_count = sum(1 for e in events if e.get('_source', {}).get('has_sigma'))
    ioc_count = sum(1 for e in events if e.get('_source', {}).get('has_ioc'))
    
    # Build enhanced prompt
    prompt = f"""You are a senior Digital Forensics and Incident Response (DFIR) analyst assistant. 
You help analysts understand Windows security events and identify attack patterns.

## CASE: {case_name}

## ANALYST'S QUESTION
{question}

## EVIDENCE CONTEXT
- {len(events)} events retrieved (showing top 15)
- {tagged_count} events were tagged by the analyst as important
- {sigma_count} events triggered SIGMA detection rules
- {ioc_count} events matched known IOC indicators

## KEY REFERENCE
**Common Attack Patterns to Consider:**
- Initial Access: Phishing (malicious docs), exposed RDP
- Execution: PowerShell, WMI, scheduled tasks
- Persistence: Services, scheduled tasks, registry run keys
- Privilege Escalation: UAC bypass, token manipulation
- Credential Access: LSASS memory, SAM database, credential dumping
- Lateral Movement: PsExec, WMI, RDP, SMB, pass-the-hash
- Exfiltration: Unusual outbound connections, large data transfers

**Logon Type Reference:**
- Type 2: Interactive (keyboard)
- Type 3: Network (SMB/mapped drive)
- Type 10: RDP
- Type 4/5: Batch/Service

## RETRIEVED EVENTS
{events_text}

## YOUR ANALYSIS INSTRUCTIONS
1. **Answer the question directly** using ONLY the events above
2. **Reference events by number**: "Event 3 shows..." or "[Event 3]"
3. **Pay special attention** to analyst-tagged (⭐) and SIGMA-flagged (⚠️) events
4. **Connect the dots**: If you see a sequence (e.g., logon → process → file access), describe the chain
5. **Identify gaps**: If the events don't fully answer the question, say what's missing
6. **Be specific**: Quote usernames, IPs, process names, timestamps when relevant
7. **DON'T fabricate**: If it's not in the events, don't invent it

## YOUR ANALYSIS
"""

    # ... rest of function same as before ...
```

---

## 4. Query-Aware Weighting

Different questions need different weighting strategies:

```python
def detect_query_type(question: str) -> str:
    """
    Detect query type to adjust retrieval strategy.
    """
    question_lower = question.lower()
    
    # Specific entity queries (exact match matters more)
    if re.search(r'\b(user|account|ip|host|computer)\s+\w+', question_lower):
        return 'entity_lookup'  # Boost keyword match
    
    # Event ID queries
    if re.search(r'\b(4624|4625|4688|7045|1102)\b', question):
        return 'event_id_specific'  # Boost keyword match
    
    # Timeline queries
    if re.search(r'\b(before|after|between|during|timeline|sequence)\b', question_lower):
        return 'temporal'  # Sort by timestamp matters
    
    # Threat hunting queries
    if re.search(r'\b(lateral|movement|persistence|exfil|credential|theft|attack)\b', question_lower):
        return 'threat_hunting'  # Boost SIGMA and IOC matches
    
    # Summary queries
    if re.search(r'\b(summarize|overview|what happened|describe)\b', question_lower):
        return 'summary'  # Diverse events, boost tagged
    
    return 'general'


def get_weights_for_query_type(query_type: str) -> Dict[str, float]:
    """
    Return optimal weights for different query types.
    """
    weights = {
        'entity_lookup': {
            'keyword': 0.7,
            'semantic': 0.3,
            'tagged_boost': 1.5,
            'sigma_boost': 1.2,
            'ioc_boost': 1.3,
        },
        'event_id_specific': {
            'keyword': 0.8,
            'semantic': 0.2,
            'tagged_boost': 1.3,
            'sigma_boost': 1.1,
            'ioc_boost': 1.2,
        },
        'temporal': {
            'keyword': 0.5,
            'semantic': 0.5,
            'tagged_boost': 2.0,  # Analyst marked important points
            'sigma_boost': 1.5,
            'ioc_boost': 1.5,
        },
        'threat_hunting': {
            'keyword': 0.4,
            'semantic': 0.6,
            'tagged_boost': 2.0,
            'sigma_boost': 2.5,  # SIGMA rules are key for threats
            'ioc_boost': 2.0,
        },
        'summary': {
            'keyword': 0.3,
            'semantic': 0.7,
            'tagged_boost': 3.0,  # Analyst curation matters most
            'sigma_boost': 1.5,
            'ioc_boost': 1.5,
        },
        'general': {
            'keyword': 0.5,
            'semantic': 0.5,
            'tagged_boost': 2.0,
            'sigma_boost': 1.5,
            'ioc_boost': 1.5,
        },
    }
    return weights.get(query_type, weights['general'])
```

---

## 5. Summary of Weight Recommendations

| Factor | Current | Recommended | Rationale |
|--------|---------|-------------|-----------|
| OpenSearch (keyword) | 40% | 30-70% (query-dependent) | Entity lookups need more keyword weight |
| Semantic similarity | 60% | 30-70% (query-dependent) | Threat questions need more semantic |
| Tagged boost | 5.0 (additive) | 2.0-3.0x (multiplicative) | Never let tagged events drop out |
| SIGMA boost | 2.5 (additive) | 1.5-2.5x (multiplicative) | Higher for threat questions |
| IOC boost | 3.5 (additive) | 1.5-2.0x (multiplicative) | Consistent but not overwhelming |

**Key Change**: Use **multiplicative** boosts instead of **additive** so they survive normalization.

---

## 6. Quick Wins (Can Implement Today)

### A. Fix the Tagged Event Problem
```python
# Before re-ranking, separate tagged events
tagged = [c for c in candidates if c.get('_source', {}).get('is_tagged')]
untagged = [c for c in candidates if not c.get('_source', {}).get('is_tagged')]

# Re-rank only untagged
# ... semantic scoring on untagged ...

# Merge: tagged first (sorted by time), then untagged (sorted by score)
final_results = sorted(tagged, key=lambda x: x['_source'].get('normalized_timestamp', ''), reverse=True)
final_results.extend(untagged_ranked)
return final_results[:max_results]
```

### B. Add Event ID Descriptions to Summary
```python
# Add this mapping and use it in create_event_summary
EVENT_DESCRIPTIONS = {4624: "Successful logon", 4625: "Failed logon", ...}
```

### C. Include Parent Process
```python
# Add to key_fields
'ParentProcessName', 'ParentImage', 'ParentCommandLine'
```
