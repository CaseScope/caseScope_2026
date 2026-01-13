# CaseScope RAG Integration Proposal
## AI-Powered Threat Hunting and Timeline Generation

**Target Hardware**: NVIDIA A2 16GB + Ollama with Qwen Instruct 14B Q5  
**Application**: CaseScope 2026 v3.64.01  
**Date**: January 2026

---

## Executive Summary

This proposal outlines a Retrieval-Augmented Generation (RAG) architecture to enhance CaseScope with AI-powered threat hunting capabilities. The system will leverage the existing ClickHouse event store, PostgreSQL metadata, and Celery task queue while introducing vector embeddings for semantic search and pattern recognition across millions of security events.

**Core Capabilities:**
1. **Related Event Hunting** - Find contextually related events around analyst/IOC-tagged events
2. **Pattern Discovery** - Detect attack patterns across 10M+ events using puzzle-piece correlation
3. **High-Confidence Tagging** - Automated AI tagging with confidence scores
4. **Timeline Composition** - Generate MITRE ATT&CK mapped incident narratives

---

## Part 1: Architecture Overview

### 1.1 System Components

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            CaseScope RAG Architecture                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────┐     ┌──────────────────┐     ┌─────────────────────────┐  │
│  │   Ollama    │     │  Pattern Store   │     │      ClickHouse         │  │
│  │  Qwen 14B   │     │   (PostgreSQL)   │     │    Events (10M+)        │  │
│  │   Q5_K_M    │     │                  │     │                         │  │
│  │  ~10GB VRAM │     │  - Attack Chains │     │  - search_blob (FTS)    │  │
│  └──────┬──────┘     │  - IOC Patterns  │     │  - ioc_types[]          │  │
│         │            │  - MITRE Mapping │     │  - ai_tags[]            │  │
│         │            │  - Puzzle Pieces │     │  - ai_confidence        │  │
│         ▼            └────────┬─────────┘     │  - ai_cluster_id        │  │
│  ┌─────────────┐              │               └───────────┬─────────────┘  │
│  │  Embedding  │              │                           │                │
│  │   Model     │◄─────────────┴───────────────────────────┘                │
│  │ (nomic-ai/  │                                                           │
│  │  nomic-     │     ┌──────────────────────────────────────────────┐     │
│  │  embed-text)│     │              Vector Store (Qdrant)            │     │
│  │  ~2GB VRAM  │     │                                               │     │
│  └──────┬──────┘     │  Collections:                                 │     │
│         │            │  - attack_patterns (768-dim, pre-seeded)      │     │
│         │            │  - event_clusters (768-dim, per-case)         │     │
│         │            │  - ioc_context (768-dim, IOC neighborhoods)   │     │
│         ▼            └──────────────────────────────────────────────┘     │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        Celery Workers                               │   │
│  │  - rag_pattern_ingest      - rag_hunt_related                      │   │
│  │  - rag_cluster_events      - rag_generate_timeline                 │   │
│  │  - rag_tag_confidence      - rag_discover_patterns                 │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1.2 Technology Stack Addition

| Component | Technology | Purpose | Resource Impact |
|-----------|------------|---------|-----------------|
| Vector DB | Qdrant | Semantic similarity search | ~2GB RAM |
| Embeddings | nomic-embed-text | Event/pattern vectorization | ~2GB VRAM |
| LLM | Qwen 14B Q5_K_M | Reasoning, synthesis | ~10GB VRAM |
| Total VRAM | | | **~12GB** (fits A2 16GB) |

### 1.3 New Dependencies

```txt
# RAG additions to requirements.txt
qdrant-client>=1.7.0          # Vector database client
sentence-transformers>=2.2.0  # Embedding models
langchain>=0.1.0              # RAG orchestration
langchain-community>=0.0.10   # Ollama integration
tiktoken>=0.5.0               # Token counting
numpy>=1.24.0                 # Vector operations
```

---

## Part 2: Attack Pattern Knowledge Base

### 2.1 Pattern Store Schema (PostgreSQL)

```sql
-- Attack pattern definitions (pre-seeded and analyst-defined)
CREATE TABLE attack_patterns (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(100),  -- e.g., 'lateral_movement', 'credential_access'
    
    -- MITRE ATT&CK mapping
    mitre_tactic VARCHAR(100),
    mitre_technique VARCHAR(50),
    mitre_sub_technique VARCHAR(50),
    
    -- Pattern definition
    pattern_type VARCHAR(50) NOT NULL,  -- 'sequence', 'co-occurrence', 'temporal'
    pattern_definition JSONB NOT NULL,  -- See pattern schemas below
    
    -- Search optimization
    required_event_ids TEXT[],          -- Event IDs that must be present
    required_channels TEXT[],           -- Channels to search
    time_window_minutes INT DEFAULT 60, -- Max time span for pattern
    
    -- Metadata
    source VARCHAR(100),  -- 'builtin', 'analyst', 'ai_discovered'
    confidence_weight FLOAT DEFAULT 1.0,
    enabled BOOLEAN DEFAULT TRUE,
    created_by VARCHAR(80),
    created_at TIMESTAMP DEFAULT NOW(),
    
    -- Embedding for semantic search
    embedding vector(768)  -- pgvector extension
);

-- Puzzle pieces: individual events that form parts of attack patterns
CREATE TABLE pattern_pieces (
    id SERIAL PRIMARY KEY,
    pattern_id INT REFERENCES attack_patterns(id),
    piece_name VARCHAR(100) NOT NULL,
    piece_order INT,  -- Order in sequence (null for co-occurrence)
    
    -- Matching criteria
    event_id_match TEXT[],        -- e.g., ['4625', '4624']
    channel_match TEXT[],
    field_conditions JSONB,       -- e.g., {"logon_type": [3, 10]}
    search_terms TEXT[],          -- Terms to match in search_blob
    
    -- Context
    description TEXT,
    is_optional BOOLEAN DEFAULT FALSE,
    
    -- Embedding for piece matching
    embedding vector(768)
);

-- AI-discovered correlations (runtime learning)
CREATE TABLE discovered_correlations (
    id SERIAL PRIMARY KEY,
    case_id INT,
    
    -- Correlation definition
    event_signature_1 JSONB,  -- First event characteristics
    event_signature_2 JSONB,  -- Correlated event characteristics
    time_offset_avg_seconds FLOAT,
    time_offset_stddev FLOAT,
    
    -- Statistics
    occurrence_count INT DEFAULT 1,
    confidence_score FLOAT,
    
    -- Review status
    analyst_reviewed BOOLEAN DEFAULT FALSE,
    promoted_to_pattern BOOLEAN DEFAULT FALSE,
    
    created_at TIMESTAMP DEFAULT NOW()
);
```

### 2.2 Pattern Definition Schemas

**Sequence Pattern** (ordered events):
```json
{
    "type": "sequence",
    "pieces": [
        {
            "name": "failed_login_burst",
            "match": {"event_id": ["4625"], "min_count": 5},
            "within_minutes": 5
        },
        {
            "name": "successful_login",
            "match": {"event_id": ["4624"], "logon_type": [3, 10]},
            "after_minutes": [0, 30]
        },
        {
            "name": "new_process",
            "match": {"event_id": ["4688"], "channel": "Security"},
            "after_minutes": [0, 60]
        }
    ],
    "total_window_minutes": 120
}
```

**Co-occurrence Pattern** (unordered, same timeframe):
```json
{
    "type": "co-occurrence",
    "pieces": [
        {"name": "service_created", "match": {"event_id": ["7045"]}},
        {"name": "scheduled_task", "match": {"event_id": ["4698"]}},
        {"name": "registry_mod", "match": {"channel": "Microsoft-Windows-Sysmon/Operational", "event_id": ["13"]}}
    ],
    "within_minutes": 60,
    "min_pieces_required": 2
}
```

### 2.3 Pre-Seeded Attack Patterns

The system ships with ~50 common attack patterns:

| Category | Pattern Name | MITRE Technique |
|----------|--------------|-----------------|
| Credential Access | Brute Force → Success | T1110 |
| Credential Access | Pass-the-Hash Detection | T1550.002 |
| Lateral Movement | RDP Lateral Movement | T1021.001 |
| Lateral Movement | PsExec-Style Execution | T1021.002 |
| Persistence | Service Installation | T1543.003 |
| Persistence | Scheduled Task Creation | T1053.005 |
| Execution | PowerShell Empire | T1059.001 |
| Execution | WMI Execution | T1047 |
| Defense Evasion | Log Clearing | T1070.001 |
| Defense Evasion | Timestomping Indicators | T1070.006 |
| Exfiltration | Large Outbound Transfer | T1048 |
| Discovery | AD Enumeration | T1087.002 |

---

## Part 3: ClickHouse Schema Extensions

### 3.1 New Columns for Events Table

```sql
-- Add AI tagging columns to events table
ALTER TABLE events ADD COLUMN ai_tags Array(String) DEFAULT [];
ALTER TABLE events ADD COLUMN ai_confidence Float32 DEFAULT 0;
ALTER TABLE events ADD COLUMN ai_cluster_id Nullable(UInt64) DEFAULT NULL;
ALTER TABLE events ADD COLUMN ai_pattern_matches Array(String) DEFAULT [];
ALTER TABLE events ADD COLUMN ai_timeline_role Nullable(String) DEFAULT NULL;
ALTER TABLE events ADD COLUMN analyst_tagged Bool DEFAULT false;
ALTER TABLE events ADD COLUMN analyst_tags Array(String) DEFAULT [];
ALTER TABLE events ADD COLUMN analyst_notes Nullable(String) DEFAULT NULL;

-- Add indexes for AI queries
ALTER TABLE events ADD INDEX idx_ai_tags ai_tags TYPE bloom_filter GRANULARITY 1;
ALTER TABLE events ADD INDEX idx_ai_confidence ai_confidence TYPE minmax GRANULARITY 1;
ALTER TABLE events ADD INDEX idx_ai_cluster_id ai_cluster_id TYPE minmax GRANULARITY 1;
```

### 3.2 Materialized Views for Pattern Detection

```sql
-- Event signature view for fast pattern matching
CREATE MATERIALIZED VIEW event_signatures
ENGINE = AggregatingMergeTree()
ORDER BY (case_id, event_id, channel)
AS SELECT
    case_id,
    event_id,
    channel,
    provider,
    countState() as event_count,
    minState(timestamp) as first_seen,
    maxState(timestamp) as last_seen,
    groupArrayState(100)(username) as usernames,
    groupArrayState(100)(process_name) as processes,
    groupArrayState(100)(src_ip) as source_ips
FROM events
GROUP BY case_id, event_id, channel, provider;

-- Time-windowed event pairs for correlation discovery
CREATE MATERIALIZED VIEW event_pairs
ENGINE = AggregatingMergeTree()
ORDER BY (case_id, event_id_1, event_id_2)
AS SELECT
    case_id,
    e1.event_id as event_id_1,
    e2.event_id as event_id_2,
    e1.channel as channel_1,
    e2.channel as channel_2,
    countState() as pair_count,
    avgState(dateDiff('second', e1.timestamp, e2.timestamp)) as avg_time_diff
FROM events e1
JOIN events e2 ON 
    e1.case_id = e2.case_id 
    AND e1.timestamp < e2.timestamp
    AND dateDiff('minute', e1.timestamp, e2.timestamp) <= 60
    AND e1.source_host = e2.source_host
GROUP BY case_id, event_id_1, event_id_2, channel_1, channel_2;
```

---

## Part 4: Vector Store Configuration

### 4.1 Qdrant Collections

```python
# Collection definitions for Qdrant
QDRANT_COLLECTIONS = {
    "attack_patterns": {
        "size": 768,  # nomic-embed-text dimension
        "distance": "Cosine",
        "description": "Pre-seeded and discovered attack patterns",
        "on_disk": False  # Keep in RAM for speed
    },
    "event_clusters": {
        "size": 768,
        "distance": "Cosine", 
        "description": "Event embeddings for similarity search",
        "on_disk": True  # Large, can be on disk
    },
    "ioc_context": {
        "size": 768,
        "distance": "Cosine",
        "description": "IOC neighborhood context for hunting",
        "on_disk": False
    },
    "timeline_fragments": {
        "size": 768,
        "distance": "Cosine",
        "description": "Narrative fragments for timeline generation",
        "on_disk": True
    }
}
```

### 4.2 Event Embedding Strategy

Given 10M+ events, we use a **representative sampling** approach:

```python
class EventEmbeddingStrategy:
    """
    Strategy for embedding large event sets efficiently.
    
    Instead of embedding every event, we:
    1. Embed "interesting" events (IOC matches, SIGMA hits, analyst-tagged)
    2. Create cluster representatives for similar events
    3. Embed pattern-matching event sequences
    """
    
    EMBEDDING_PRIORITIES = [
        ("analyst_tagged", 1.0),      # Always embed analyst-tagged
        ("ioc_types", 0.9),           # High priority for IOC matches
        ("rule_level", 0.8),          # SIGMA/Hayabusa hits
        ("rare_event_id", 0.6),       # Uncommon event IDs
        ("cluster_representative", 0.5),  # 1 per N similar events
    ]
    
    CLUSTER_SAMPLING_RATE = 100  # 1 embedding per 100 similar events
    MAX_EMBEDDINGS_PER_CASE = 50000  # Cap for memory management
```

---

## Part 5: Core RAG Workflows

### 5.1 Pattern Ingestion Task

```python
# tasks/rag_tasks.py

@celery_app.task(bind=True, name='tasks.rag_ingest_patterns')
def rag_ingest_patterns(self, refresh_builtins: bool = False):
    """
    Ingest attack patterns into vector store.
    
    1. Load patterns from PostgreSQL
    2. Generate embeddings for pattern descriptions
    3. Upsert to Qdrant attack_patterns collection
    """
    from models.rag import AttackPattern
    from utils.rag_embeddings import get_embedding_model
    from utils.rag_vectorstore import get_qdrant_client
    
    embed_model = get_embedding_model()
    qdrant = get_qdrant_client()
    
    patterns = AttackPattern.query.filter_by(enabled=True).all()
    
    for pattern in patterns:
        # Create rich text for embedding
        pattern_text = f"""
        Attack Pattern: {pattern.name}
        Category: {pattern.category}
        MITRE: {pattern.mitre_tactic} / {pattern.mitre_technique}
        Description: {pattern.description}
        Event IDs: {', '.join(pattern.required_event_ids or [])}
        Indicators: {json.dumps(pattern.pattern_definition)}
        """
        
        embedding = embed_model.encode(pattern_text)
        
        qdrant.upsert(
            collection_name="attack_patterns",
            points=[{
                "id": pattern.id,
                "vector": embedding.tolist(),
                "payload": {
                    "name": pattern.name,
                    "mitre_technique": pattern.mitre_technique,
                    "pattern_type": pattern.pattern_type,
                    "time_window": pattern.time_window_minutes
                }
            }]
        )
    
    return {"patterns_ingested": len(patterns)}
```

### 5.2 Related Event Hunting

```python
@celery_app.task(bind=True, name='tasks.rag_hunt_related')
def rag_hunt_related(
    self,
    case_id: int,
    anchor_event_ids: List[str],  # ClickHouse row IDs
    time_window_hours: int = 24,
    max_results: int = 100
) -> Dict[str, Any]:
    """
    Hunt for events related to analyst-tagged or IOC-matched events.
    
    Process:
    1. Get anchor events from ClickHouse
    2. Build context embedding from anchor events
    3. Query pattern store for matching attack patterns
    4. Search surrounding events matching pattern pieces
    5. Score and rank results by pattern confidence
    """
    app = get_flask_app()
    
    with app.app_context():
        from utils.clickhouse import get_fresh_client
        from utils.rag_embeddings import get_embedding_model
        from utils.rag_vectorstore import get_qdrant_client
        from utils.rag_llm import get_ollama_client
        
        ch_client = get_fresh_client()
        embed_model = get_embedding_model()
        qdrant = get_qdrant_client()
        llm = get_ollama_client()
        
        # Step 1: Get anchor events
        anchor_query = f"""
            SELECT *
            FROM events
            WHERE case_id = {case_id}
              AND rowNumberInAllBlocks() IN ({','.join(anchor_event_ids)})
        """
        anchors = ch_client.query(anchor_query).result_rows
        
        if not anchors:
            return {"error": "No anchor events found", "results": []}
        
        # Step 2: Build context from anchors
        anchor_context = build_event_context(anchors)
        context_embedding = embed_model.encode(anchor_context)
        
        # Step 3: Find matching attack patterns
        pattern_matches = qdrant.search(
            collection_name="attack_patterns",
            query_vector=context_embedding.tolist(),
            limit=10,
            score_threshold=0.6
        )
        
        # Step 4: Search for pattern pieces in time window
        results = []
        
        for anchor in anchors:
            anchor_time = anchor['timestamp']
            time_start = anchor_time - timedelta(hours=time_window_hours)
            time_end = anchor_time + timedelta(hours=time_window_hours)
            
            for pattern_match in pattern_matches:
                pattern = load_pattern(pattern_match.id)
                
                # Search for each piece in the pattern
                found_pieces = search_pattern_pieces(
                    ch_client, case_id, pattern,
                    time_start, time_end,
                    anchor['source_host']
                )
                
                if len(found_pieces) >= pattern.min_pieces:
                    results.append({
                        "pattern_name": pattern.name,
                        "mitre_technique": pattern.mitre_technique,
                        "anchor_event": anchor,
                        "related_events": found_pieces,
                        "confidence": calculate_confidence(pattern_match.score, found_pieces),
                        "time_span": calculate_time_span(found_pieces)
                    })
        
        # Step 5: Use LLM to synthesize and explain findings
        if results:
            synthesis = await synthesize_with_llm(llm, results)
            for result in results:
                result['ai_explanation'] = synthesis.get(result['pattern_name'])
        
        return {
            "success": True,
            "anchor_count": len(anchors),
            "patterns_checked": len(pattern_matches),
            "results": sorted(results, key=lambda x: x['confidence'], reverse=True)
        }
```

### 5.3 Large-Scale Pattern Discovery (The "Puzzle" Approach)

```python
@celery_app.task(bind=True, name='tasks.rag_discover_patterns')
def rag_discover_patterns(
    self,
    case_id: int,
    chunk_size: int = 100000,
    confidence_threshold: float = 0.7
) -> Dict[str, Any]:
    """
    Scan all events for attack patterns using chunked processing.
    
    The "Puzzle Piece" Approach:
    1. Identify "interesting" events (4625s, rare events, IOC matches)
    2. For each interesting event, look for other puzzle pieces
    3. Score complete and partial pattern matches
    4. Tag events with pattern associations and confidence
    
    Optimized for 10M+ events with chunked processing.
    """
    app = get_flask_app()
    
    with app.app_context():
        from utils.clickhouse import get_fresh_client
        from models.rag import AttackPattern
        
        ch_client = get_fresh_client()
        
        # Get total event count
        total_result = ch_client.query(
            f"SELECT count() FROM events WHERE case_id = {case_id}"
        )
        total_events = total_result.result_rows[0][0]
        
        self.update_state(state='PROGRESS', meta={
            'progress': 0,
            'status': f'Scanning {total_events:,} events...',
            'total_events': total_events
        })
        
        # Load all active patterns
        patterns = AttackPattern.query.filter_by(enabled=True).all()
        pattern_triggers = build_pattern_triggers(patterns)
        
        discovered = []
        events_processed = 0
        events_tagged = 0
        
        # Process in chunks
        offset = 0
        while offset < total_events:
            chunk = ch_client.query(f"""
                SELECT *
                FROM events
                WHERE case_id = {case_id}
                ORDER BY timestamp
                LIMIT {chunk_size}
                OFFSET {offset}
            """).result_rows
            
            # Find trigger events (potential pattern starters)
            triggers = identify_triggers(chunk, pattern_triggers)
            
            for trigger in triggers:
                # Look for pattern completions around this trigger
                matches = search_pattern_completions(
                    ch_client, case_id, trigger,
                    patterns, time_window_hours=24
                )
                
                for match in matches:
                    if match['confidence'] >= confidence_threshold:
                        discovered.append(match)
                        
                        # Tag participating events
                        tag_events_with_pattern(
                            ch_client, case_id,
                            match['event_ids'],
                            match['pattern_name'],
                            match['confidence']
                        )
                        events_tagged += len(match['event_ids'])
            
            events_processed += len(chunk)
            offset += chunk_size
            
            self.update_state(state='PROGRESS', meta={
                'progress': int((events_processed / total_events) * 100),
                'status': f'Processed {events_processed:,} / {total_events:,}',
                'patterns_found': len(discovered)
            })
        
        # Deduplicate overlapping patterns
        discovered = deduplicate_patterns(discovered)
        
        return {
            'success': True,
            'total_events': total_events,
            'events_tagged': events_tagged,
            'patterns_discovered': len(discovered),
            'pattern_summary': summarize_patterns(discovered),
            'high_confidence': [p for p in discovered if p['confidence'] >= 0.9]
        }


def identify_triggers(events: List, pattern_triggers: Dict) -> List:
    """
    Identify events that could be the start of an attack pattern.
    
    Trigger types:
    - 4625: Failed login (potential brute force start)
    - 4624 with logon_type 3/10: Network/RDP login (lateral movement)
    - 4688 with suspicious process: Execution
    - 7045: Service creation (persistence)
    - etc.
    """
    triggers = []
    
    for event in events:
        event_id = event['event_id']
        
        if event_id in pattern_triggers:
            for pattern_id in pattern_triggers[event_id]:
                triggers.append({
                    'event': event,
                    'pattern_ids': pattern_triggers[event_id],
                    'trigger_type': get_trigger_type(event_id)
                })
    
    return triggers
```

### 5.4 High-Confidence Event Tagging

```python
@celery_app.task(bind=True, name='tasks.rag_tag_confidence')
def rag_tag_confidence(
    self,
    case_id: int,
    min_confidence: float = 0.8
) -> Dict[str, Any]:
    """
    Apply AI confidence tags to events based on pattern matches.
    
    Tagging levels:
    - ai_confidence >= 0.9: HIGH_CONFIDENCE
    - ai_confidence >= 0.7: MEDIUM_CONFIDENCE  
    - ai_confidence >= 0.5: LOW_CONFIDENCE
    
    Events tagged with HIGH_CONFIDENCE are auto-marked for timeline inclusion.
    """
    app = get_flask_app()
    
    with app.app_context():
        from utils.clickhouse import get_fresh_client
        
        ch_client = get_fresh_client()
        
        # Get events with pattern matches but not yet confidence-tagged
        events_to_tag = ch_client.query(f"""
            SELECT rowNumberInAllBlocks() as row_id,
                   ai_pattern_matches,
                   ai_confidence
            FROM events
            WHERE case_id = {case_id}
              AND length(ai_pattern_matches) > 0
              AND ai_confidence = 0
        """).result_rows
        
        tag_updates = []
        
        for event in events_to_tag:
            # Calculate confidence from pattern matches
            confidence = calculate_event_confidence(event['ai_pattern_matches'])
            
            if confidence >= min_confidence:
                tag = 'HIGH_CONFIDENCE' if confidence >= 0.9 else 'MEDIUM_CONFIDENCE'
                include_timeline = confidence >= 0.9
                
                tag_updates.append({
                    'row_id': event['row_id'],
                    'confidence': confidence,
                    'tag': tag,
                    'timeline': include_timeline
                })
        
        # Batch update ClickHouse
        if tag_updates:
            update_query = build_batch_update(case_id, tag_updates)
            ch_client.command(update_query)
        
        return {
            'success': True,
            'events_tagged': len(tag_updates),
            'high_confidence': len([t for t in tag_updates if t['tag'] == 'HIGH_CONFIDENCE']),
            'medium_confidence': len([t for t in tag_updates if t['tag'] == 'MEDIUM_CONFIDENCE'])
        }
```

### 5.5 Timeline Composition

```python
@celery_app.task(bind=True, name='tasks.rag_generate_timeline')
def rag_generate_timeline(
    self,
    case_id: int,
    include_analyst_tags: bool = True,
    include_ai_high_confidence: bool = True,
    mitre_mapping: bool = True
) -> Dict[str, Any]:
    """
    Generate an incident timeline using analyst and AI tagged events.
    
    Process:
    1. Collect tagged events (analyst + AI high confidence)
    2. Cluster into incident phases
    3. Map to MITRE ATT&CK framework
    4. Use LLM to generate narrative descriptions
    5. Produce structured timeline with explanations
    """
    app = get_flask_app()
    
    with app.app_context():
        from utils.clickhouse import get_fresh_client
        from utils.rag_llm import get_ollama_client
        from utils.mitre_mapper import MITREMapper
        
        ch_client = get_fresh_client()
        llm = get_ollama_client()
        mitre = MITREMapper()
        
        # Step 1: Collect timeline-worthy events
        timeline_query = f"""
            SELECT *
            FROM events
            WHERE case_id = {case_id}
              AND (
                  analyst_tagged = true
                  OR (ai_confidence >= 0.9 AND ai_timeline_role IS NOT NULL)
                  OR length(ioc_types) > 0
                  OR rule_level IN ('high', 'critical')
              )
            ORDER BY timestamp ASC
        """
        events = ch_client.query(timeline_query).result_rows
        
        if not events:
            return {"error": "No timeline-worthy events found", "timeline": []}
        
        self.update_state(state='PROGRESS', meta={
            'progress': 20,
            'status': f'Processing {len(events)} events for timeline...'
        })
        
        # Step 2: Cluster into phases
        phases = cluster_into_phases(events)
        
        self.update_state(state='PROGRESS', meta={
            'progress': 40,
            'status': f'Identified {len(phases)} incident phases...'
        })
        
        # Step 3: Map to MITRE
        for phase in phases:
            phase['mitre_tactics'] = []
            phase['mitre_techniques'] = []
            
            for event in phase['events']:
                if event.get('mitre_tactics'):
                    phase['mitre_tactics'].extend(event['mitre_tactics'])
                if event.get('ai_pattern_matches'):
                    for pattern_name in event['ai_pattern_matches']:
                        technique = mitre.get_technique_for_pattern(pattern_name)
                        if technique:
                            phase['mitre_techniques'].append(technique)
            
            phase['mitre_tactics'] = list(set(phase['mitre_tactics']))
            phase['mitre_techniques'] = list(set(phase['mitre_techniques']))
        
        self.update_state(state='PROGRESS', meta={
            'progress': 60,
            'status': 'Generating narrative with AI...'
        })
        
        # Step 4: Generate narrative for each phase
        timeline_entries = []
        
        for i, phase in enumerate(phases):
            # Build context for LLM
            phase_context = build_phase_context(phase)
            
            # Generate narrative
            narrative_prompt = f"""
            Analyze this incident phase and provide a concise forensic narrative.
            
            Phase {i + 1} of {len(phases)}
            Time Range: {phase['start_time']} to {phase['end_time']}
            Event Count: {len(phase['events'])}
            
            Key Events:
            {phase_context}
            
            MITRE Tactics: {', '.join(phase['mitre_tactics']) or 'Unknown'}
            MITRE Techniques: {', '.join(phase['mitre_techniques']) or 'Unknown'}
            
            Provide:
            1. A 2-3 sentence summary of what happened in this phase
            2. The likely attacker objective
            3. Key indicators (IOCs, usernames, processes)
            4. Confidence level (High/Medium/Low) with brief justification
            
            Format as JSON.
            """
            
            response = llm.generate(
                model="qwen2.5:14b-instruct-q5_K_M",
                prompt=narrative_prompt,
                format="json"
            )
            
            narrative = parse_llm_response(response)
            
            timeline_entries.append({
                'phase_number': i + 1,
                'start_time': phase['start_time'].isoformat(),
                'end_time': phase['end_time'].isoformat(),
                'event_count': len(phase['events']),
                'event_ids': [e['event_id'] for e in phase['events']],
                'mitre_tactics': phase['mitre_tactics'],
                'mitre_techniques': phase['mitre_techniques'],
                'summary': narrative.get('summary', ''),
                'attacker_objective': narrative.get('objective', ''),
                'key_indicators': narrative.get('indicators', []),
                'confidence': narrative.get('confidence', 'Medium'),
                'confidence_justification': narrative.get('justification', ''),
                'source_events': [
                    {
                        'timestamp': e['timestamp'].isoformat(),
                        'event_id': e['event_id'],
                        'description': e.get('rule_title') or f"Event {e['event_id']}",
                        'tagged_by': 'analyst' if e.get('analyst_tagged') else 'ai'
                    }
                    for e in phase['events'][:10]  # Limit to top 10 for display
                ]
            })
            
            self.update_state(state='PROGRESS', meta={
                'progress': 60 + int((i / len(phases)) * 35),
                'status': f'Generated narrative for phase {i + 1}/{len(phases)}'
            })
        
        # Step 5: Generate executive summary
        exec_summary = generate_executive_summary(llm, timeline_entries)
        
        return {
            'success': True,
            'case_id': case_id,
            'generated_at': datetime.utcnow().isoformat(),
            'total_events': len(events),
            'phase_count': len(timeline_entries),
            'executive_summary': exec_summary,
            'timeline': timeline_entries,
            'mitre_coverage': calculate_mitre_coverage(timeline_entries)
        }


def cluster_into_phases(events: List, gap_threshold_minutes: int = 120) -> List:
    """
    Cluster events into incident phases based on time gaps.
    
    A new phase starts when there's a gap > threshold between events.
    """
    if not events:
        return []
    
    phases = []
    current_phase = {
        'events': [events[0]],
        'start_time': events[0]['timestamp'],
        'end_time': events[0]['timestamp']
    }
    
    for event in events[1:]:
        time_gap = (event['timestamp'] - current_phase['end_time']).total_seconds() / 60
        
        if time_gap > gap_threshold_minutes:
            # Start new phase
            phases.append(current_phase)
            current_phase = {
                'events': [event],
                'start_time': event['timestamp'],
                'end_time': event['timestamp']
            }
        else:
            current_phase['events'].append(event)
            current_phase['end_time'] = event['timestamp']
    
    phases.append(current_phase)
    return phases
```

---

## Part 6: Integration Points

### 6.1 New API Endpoints

```python
# routes/rag_api.py

rag_bp = Blueprint('rag', __name__, url_prefix='/api/rag')

@rag_bp.route('/hunt/related', methods=['POST'])
@login_required
def hunt_related():
    """Start related event hunting task"""
    data = request.json
    case_id = data.get('case_id')
    anchor_events = data.get('anchor_events', [])
    time_window = data.get('time_window_hours', 24)
    
    task = rag_hunt_related.delay(case_id, anchor_events, time_window)
    return jsonify({'success': True, 'task_id': task.id})

@rag_bp.route('/patterns/discover', methods=['POST'])
@login_required  
def discover_patterns():
    """Start pattern discovery task"""
    data = request.json
    case_id = data.get('case_id')
    
    task = rag_discover_patterns.delay(case_id)
    return jsonify({'success': True, 'task_id': task.id})

@rag_bp.route('/timeline/generate', methods=['POST'])
@login_required
def generate_timeline():
    """Start timeline generation task"""
    data = request.json
    case_id = data.get('case_id')
    
    task = rag_generate_timeline.delay(
        case_id,
        include_analyst_tags=data.get('include_analyst', True),
        include_ai_high_confidence=data.get('include_ai', True),
        mitre_mapping=data.get('mitre_mapping', True)
    )
    return jsonify({'success': True, 'task_id': task.id})

@rag_bp.route('/status/<task_id>')
@login_required
def get_task_status(task_id):
    """Get RAG task status"""
    from celery.result import AsyncResult
    result = AsyncResult(task_id, app=celery_app)
    
    if result.state == 'PENDING':
        return jsonify({'state': 'pending', 'progress': 0})
    elif result.state == 'PROGRESS':
        return jsonify({
            'state': 'progress',
            'progress': result.info.get('progress', 0),
            'status': result.info.get('status', '')
        })
    elif result.state == 'SUCCESS':
        return jsonify({'state': 'completed', 'result': result.result})
    else:
        return jsonify({'state': 'failed', 'error': str(result.info)})

@rag_bp.route('/patterns', methods=['GET'])
@login_required
def list_patterns():
    """List available attack patterns"""
    from models.rag import AttackPattern
    patterns = AttackPattern.query.filter_by(enabled=True).all()
    return jsonify({
        'success': True,
        'patterns': [p.to_dict() for p in patterns]
    })

@rag_bp.route('/patterns', methods=['POST'])
@login_required
def create_pattern():
    """Create custom attack pattern"""
    data = request.json
    # ... pattern creation logic
```

### 6.2 UI Integration Points

**Hunting Tab Enhancements:**
```html
<!-- Add to case_hunting.html -->
<div class="hunting-ai-section">
    <h3>🤖 AI-Powered Hunting</h3>
    
    <!-- Hunt Related Events -->
    <div class="ai-card">
        <h4>Hunt Related Events</h4>
        <p>Find events related to selected or tagged items</p>
        <div class="ai-options">
            <label>
                <input type="checkbox" id="huntFromIOC" checked>
                Include IOC-tagged events
            </label>
            <label>
                <input type="checkbox" id="huntFromAnalyst" checked>
                Include analyst-tagged events
            </label>
            <label>
                Time window:
                <select id="huntTimeWindow">
                    <option value="12">±12 hours</option>
                    <option value="24" selected>±24 hours</option>
                    <option value="48">±48 hours</option>
                    <option value="168">±7 days</option>
                </select>
            </label>
        </div>
        <button class="btn btn-primary" onclick="startRelatedHunt()">
            🔍 Hunt Related
        </button>
    </div>
    
    <!-- Pattern Discovery -->
    <div class="ai-card">
        <h4>Discover Attack Patterns</h4>
        <p>Scan all events for known attack patterns (puzzle pieces)</p>
        <div class="pattern-stats" id="patternStats">
            <!-- Populated by JS -->
        </div>
        <button class="btn btn-primary" onclick="startPatternDiscovery()">
            🧩 Find Patterns
        </button>
    </div>
    
    <!-- Timeline Generation -->
    <div class="ai-card">
        <h4>Generate Timeline</h4>
        <p>Create MITRE-mapped incident timeline from tagged events</p>
        <button class="btn btn-primary" onclick="generateTimeline()">
            📅 Generate Timeline
        </button>
    </div>
</div>
```

### 6.3 Analyst Tagging Integration

```python
# Add to routes/api.py

@api_bp.route('/events/<int:case_id>/tag', methods=['POST'])
@login_required
def tag_events(case_id):
    """
    Allow analysts to tag events for RAG processing.
    
    Tags:
    - interesting: Mark for pattern hunting
    - suspicious: High priority
    - benign: Confirmed not malicious
    - timeline: Include in timeline
    - custom tags: Free-form
    """
    data = request.json
    event_ids = data.get('event_ids', [])
    tags = data.get('tags', [])
    notes = data.get('notes', '')
    
    from utils.clickhouse import get_fresh_client
    client = get_fresh_client()
    
    # Update events with analyst tags
    for event_id in event_ids:
        client.command(f"""
            ALTER TABLE events UPDATE
                analyst_tagged = true,
                analyst_tags = arrayConcat(analyst_tags, {tags}),
                analyst_notes = '{notes.replace("'", "''")}'
            WHERE case_id = {case_id}
              AND rowNumberInAllBlocks() = {event_id}
        """)
    
    return jsonify({
        'success': True,
        'events_tagged': len(event_ids)
    })
```

---

## Part 7: Hardware Optimization

### 7.1 NVIDIA A2 16GB Memory Management

```python
# utils/rag_memory.py

class GPUMemoryManager:
    """
    Manage GPU memory for A2 16GB with multiple models.
    
    Typical allocation:
    - Qwen 14B Q5_K_M: ~10GB
    - nomic-embed-text: ~2GB
    - Buffer for inference: ~4GB
    
    Strategy: Keep LLM loaded, load/unload embeddings as needed
    """
    
    VRAM_TOTAL_GB = 16
    LLM_VRAM_GB = 10
    EMBED_VRAM_GB = 2
    BUFFER_GB = 4
    
    def __init__(self):
        self.llm_loaded = False
        self.embed_loaded = False
    
    def ensure_llm_loaded(self):
        """Ensure LLM is in GPU memory"""
        if not self.llm_loaded:
            # Ollama handles this automatically, but we track state
            self.llm_loaded = True
    
    def ensure_embeddings_loaded(self):
        """Load embedding model, potentially unloading other models"""
        if not self.embed_loaded:
            # With Ollama managing Qwen, we use sentence-transformers
            # which loads to available VRAM
            self.embed_loaded = True
    
    def get_batch_size(self, operation: str) -> int:
        """Get optimal batch size based on available memory"""
        if operation == 'embedding':
            return 32  # Embed 32 events at a time
        elif operation == 'llm_inference':
            return 1   # One prompt at a time for Qwen
        elif operation == 'pattern_search':
            return 1000  # ClickHouse batch size
        return 100
```

### 7.2 Ollama Configuration

```yaml
# /etc/ollama/config.yaml
models:
  qwen2.5:14b-instruct-q5_K_M:
    gpu_layers: 99  # All layers on GPU
    context_size: 8192
    batch_size: 512
    threads: 8  # CPU threads for non-GPU ops
    
# Keep model loaded for faster inference
OLLAMA_KEEP_ALIVE: "24h"
OLLAMA_NUM_PARALLEL: 1  # Single concurrent request
OLLAMA_MAX_LOADED_MODELS: 1  # Only Qwen loaded
```

### 7.3 Embedding Model Selection

```python
# Use nomic-embed-text via Ollama for consistency
# Alternatively, use sentence-transformers if VRAM is tight

EMBEDDING_CONFIG = {
    "primary": {
        "model": "nomic-embed-text",
        "provider": "ollama",
        "dimension": 768,
        "vram_gb": 2
    },
    "fallback": {
        "model": "all-MiniLM-L6-v2",
        "provider": "sentence-transformers",
        "dimension": 384,
        "vram_gb": 0.5  # Much smaller
    }
}
```

---

## Part 8: Deployment Steps

### 8.1 Installation Sequence

```bash
# 1. Install Qdrant (vector database)
docker run -d --name qdrant \
    -p 6333:6333 -p 6334:6334 \
    -v /opt/casescope/qdrant:/qdrant/storage \
    qdrant/qdrant

# 2. Install pgvector extension (PostgreSQL)
sudo apt install postgresql-16-pgvector
psql -d casescope -c "CREATE EXTENSION vector;"

# 3. Pull Ollama models
ollama pull qwen2.5:14b-instruct-q5_K_M
ollama pull nomic-embed-text

# 4. Install Python dependencies
pip install qdrant-client sentence-transformers langchain langchain-community

# 5. Run migrations
flask db upgrade

# 6. Initialize pattern store
flask rag init-patterns

# 7. Start Celery worker with RAG tasks
celery -A tasks worker -Q rag,default -c 2
```

### 8.2 Configuration Additions

```python
# Add to config.py

class RAGConfig:
    """RAG-specific configuration"""
    
    # Qdrant
    QDRANT_HOST = os.environ.get('QDRANT_HOST', 'localhost')
    QDRANT_PORT = int(os.environ.get('QDRANT_PORT', 6333))
    
    # Ollama
    OLLAMA_HOST = os.environ.get('OLLAMA_HOST', 'http://localhost:11434')
    OLLAMA_MODEL = os.environ.get('OLLAMA_MODEL', 'qwen2.5:14b-instruct-q5_K_M')
    OLLAMA_EMBED_MODEL = os.environ.get('OLLAMA_EMBED_MODEL', 'nomic-embed-text')
    
    # Processing
    RAG_BATCH_SIZE = int(os.environ.get('RAG_BATCH_SIZE', 100))
    RAG_MAX_CONTEXT_TOKENS = int(os.environ.get('RAG_MAX_CONTEXT_TOKENS', 6000))
    RAG_CONFIDENCE_THRESHOLD = float(os.environ.get('RAG_CONFIDENCE_THRESHOLD', 0.7))
    
    # Pattern discovery
    RAG_TIME_WINDOW_HOURS = int(os.environ.get('RAG_TIME_WINDOW_HOURS', 24))
    RAG_MIN_PATTERN_PIECES = int(os.environ.get('RAG_MIN_PATTERN_PIECES', 2))
```

---

## Part 9: Performance Estimates

### 9.1 Processing Times (NVIDIA A2 16GB)

| Operation | Events | Estimated Time |
|-----------|--------|----------------|
| Related Event Hunt | 1000 anchors | ~5 minutes |
| Pattern Discovery | 1M events | ~15 minutes |
| Pattern Discovery | 10M events | ~2.5 hours |
| Timeline Generation | 500 tagged events | ~3 minutes |
| Embedding Generation | 10K events | ~2 minutes |

### 9.2 Memory Usage

| Component | RAM | VRAM |
|-----------|-----|------|
| Qdrant | 2-4GB | - |
| PostgreSQL (patterns) | 500MB | - |
| Qwen 14B inference | 2GB | 10GB |
| Embedding model | 500MB | 2GB |
| Celery worker | 1GB | - |
| **Total** | **~8GB** | **~12GB** |

---

## Part 10: Future Enhancements

### 10.1 Phase 2 Roadmap

1. **Real-time Pattern Detection**: Stream processing for live event ingestion
2. **Cross-Case Pattern Learning**: Discover patterns across multiple cases
3. **Automated IOC Extraction**: LLM-powered IOC extraction from narratives
4. **Report Generation**: Full incident report generation from timelines
5. **Threat Intelligence Integration**: Correlate with external TI feeds

### 10.2 Model Upgrade Path

When hardware allows, consider:
- Qwen 32B for better reasoning
- Dedicated embedding GPU
- Distributed Qdrant for larger cases

---

## Appendix A: Sample Pattern Definitions

### A.1 Brute Force Attack Pattern

```json
{
    "name": "Brute Force to Successful Login",
    "category": "credential_access",
    "mitre_tactic": "Credential Access",
    "mitre_technique": "T1110",
    "pattern_type": "sequence",
    "pattern_definition": {
        "type": "sequence",
        "pieces": [
            {
                "name": "failed_logins",
                "match": {
                    "event_id": ["4625"],
                    "channel": "Security"
                },
                "aggregation": {
                    "min_count": 5,
                    "within_minutes": 10,
                    "group_by": ["username", "src_ip"]
                }
            },
            {
                "name": "successful_login",
                "match": {
                    "event_id": ["4624"],
                    "channel": "Security",
                    "logon_type": [3, 10]
                },
                "after_minutes": [0, 30],
                "same_fields": ["username"]
            }
        ],
        "total_window_minutes": 60
    },
    "required_event_ids": ["4625", "4624"],
    "required_channels": ["Security"],
    "confidence_weight": 0.9
}
```

### A.2 Lateral Movement Pattern

```json
{
    "name": "RDP Lateral Movement Chain",
    "category": "lateral_movement",
    "mitre_tactic": "Lateral Movement",
    "mitre_technique": "T1021.001",
    "pattern_type": "sequence",
    "pattern_definition": {
        "type": "sequence",
        "pieces": [
            {
                "name": "rdp_connection",
                "match": {
                    "event_id": ["4624"],
                    "logon_type": [10]
                }
            },
            {
                "name": "process_execution",
                "match": {
                    "event_id": ["4688"],
                    "search_terms": ["cmd.exe", "powershell.exe", "wmic.exe"]
                },
                "after_minutes": [0, 30]
            },
            {
                "name": "outbound_rdp",
                "match": {
                    "event_id": ["1024"],
                    "channel": "Microsoft-Windows-TerminalServices-RDPClient/Operational"
                },
                "after_minutes": [0, 60],
                "is_optional": true
            }
        ],
        "total_window_minutes": 120
    }
}
```

---

## Appendix B: MITRE ATT&CK Mapping Reference

The system maintains a mapping from patterns to MITRE techniques:

| Pattern Category | Common Techniques |
|-----------------|-------------------|
| Initial Access | T1566, T1190, T1133 |
| Execution | T1059, T1047, T1053 |
| Persistence | T1543, T1547, T1136 |
| Privilege Escalation | T1068, T1548, T1134 |
| Defense Evasion | T1070, T1562, T1036 |
| Credential Access | T1110, T1003, T1552 |
| Discovery | T1087, T1082, T1083 |
| Lateral Movement | T1021, T1091, T1570 |
| Collection | T1560, T1074, T1005 |
| Exfiltration | T1048, T1041, T1567 |
| Impact | T1486, T1490, T1489 |

---

*Document prepared for CaseScope RAG Integration Project*
*Last updated: January 2026*
