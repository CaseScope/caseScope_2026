# CaseScope AI Architecture: Honest Assessment & Redesign

## What You Asked For

1. IOC extraction from EDR reports (AI-first with regex catch, or regex-only)
2. Case analysis: behavioral profiling → pattern detection → IOC-anchored timeline
3. Real-time analyst chat with the agent

## What You Actually Have (After 17K+ Lines Reviewed)

### The Good

**Your deterministic pipeline is genuinely strong.** The behavioral profiler, peer clustering, gap detectors, Hayabusa correlator, and attack chain builder are well-engineered. The `pattern_rules.py` with 59 temporal/simple patterns across 7 MITRE categories and ClickHouse queries is solid forensic engineering. The confidence scoring with factor breakdowns (`calculate_confidence()`) is thoughtful. The parsers (EVTX with parallel EvtxECmd + Hayabusa, memory, PCAP, IIS, SonicWall) are production-quality.

**Your IOC extraction already works.** `ioc_extractor.py` at 2,206 lines handles AI extraction → regex fallback, defanging, type-aware dedup, known-system/known-user filtering, and hostname/username IOC generation. This is your most complete AI feature.

**Your "Ask AI" review endpoint exists.** `/api/rag/review-events` already accepts events, builds context, streams responses, and supports follow-up with conversation history. It's not a full chat agent, but the foundation is there.

### The Problems

**Problem 1: You have THREE separate pattern detection systems that don't talk to each other.**

| System | Location | Patterns | How It Works |
|--------|----------|----------|-------------|
| Pattern Event Mappings | `pattern_event_mappings.py` + `candidate_extractor.py` + `ai_correlation_analyzer.py` | 3 (PtH, PtT, DCSync-ish) | Extracts candidates → sends to DeepSeek-R1 for AI validation |
| Pattern Rules | `models/pattern_rules.py` + `detect_attack_patterns` task | 59 across 7 MITRE categories | ClickHouse queries → rule-based confidence scoring |
| RAG Patterns | `models/rag.py` + `AttackPattern` model + `rag_discover_patterns` task | Dynamic (synced from OpenCTI, MITRE ATT&CK, Sigma, Hayabusa) | Semantic search + ClickHouse queries |

System 1 has only 3 patterns and uses the slow DeepSeek-R1 pipeline. System 2 has 59 well-crafted patterns with good confidence scoring but no AI enhancement. System 3 syncs hundreds of patterns from external sources but shares no confidence logic with System 2. An analyst doesn't know which system found what, or why different confidence scores mean different things.

**Problem 2: The CaseAnalyzer runs everything sequentially regardless of case content.**

`case_analyzer.py` runs 8 phases in order: behavioral profiling → peer clustering → gap detection → Hayabusa correlation → pattern analysis → OpenCTI enrichment → suggested actions → finalize. On a 40M artifact case, it runs every pattern query against ClickHouse even if the relevant event IDs don't exist in the case. There's no census, no early filtering, no parallelization.

**Problem 3: The AI validates but never investigates.**

DeepSeek-R1 receives pre-extracted candidate events and answers "does this look like Pass-the-Hash: yes/no." It never decides what to look at next. It never follows a thread. It never says "I see suspicious PowerShell on HOST-A, let me check what network connections HOST-A made in the next 10 minutes." The AI is a rubber stamp, not an investigator.

**Problem 4: IOC-to-timeline reconstruction doesn't exist as a coherent pipeline.**

You have `rag_hunt_related` (finds events near high-severity anchors), `rag_generate_timeline` (clusters events into time-phases and narrates them), and `ai_timeline_generator.py` (groups similar events and generates timeline reports). But none of them start from IOCs, pivot through related events, and build a causal chain. They're all "grab events in a time window and describe them."

**Problem 5: The real-time chat has no tools.**

Your `/api/rag/review-events` endpoint dumps up to 150 events into a prompt and asks the LLM to analyze them. The LLM can't query ClickHouse for more context. It can't look up an IOC. It can't check behavioral profiles. It can't pull Hayabusa detections for a specific host. It's a one-shot "here's everything, tell me what you see" — which works for small event sets but falls apart for real investigations where the analyst needs to drill down.

**Problem 6: DeepSeek-R1 is the wrong model for your hardware and use case.**

R1 is a reasoning model that generates long internal chain-of-thought before answering. On the A2 with 4.5 TFLOPS, that means 30-60 second inference times for complex prompts. Your `_parse_fallback_response()` code in `ai_correlation_analyzer.py` proves R1's structured output is unreliable — you're regex-parsing its free-text responses when JSON parsing fails. For agentic tool-use where you need fast, reliable structured output, R1 is the wrong choice.

---

## What I'd Remove

### 1. The `pattern_event_mappings.py` + `candidate_extractor.py` + `ai_correlation_analyzer.py` pipeline (System 1)

**Why:** 3 patterns, 2,700+ lines of code, the slowest inference path. System 2 (`pattern_rules.py`) already covers the same attack types with 59 patterns and doesn't need AI validation — the temporal ClickHouse queries and confidence scoring are deterministic and fast. The AI's "yes this looks like PtH" adds marginal value over a well-crafted temporal SQL query that already checks for the right sequence of event IDs in the right time window.

**What you keep:** The `CandidateExtractor` concept is good — extracting anchor/supporting/context events with behavioral context attached. Fold that into the unified pipeline (below) as the detail-fetcher when the analyst wants to drill into a specific finding.

### 2. The RAG semantic pattern discovery (`_get_semantic_pattern_suggestions`)

**Why:** You embed 25 sampled events, search Qdrant for similar attack patterns, then run those patterns' ClickHouse queries anyway. The semantic search adds a slow embedding step to decide which SQL queries to run. A 10-millisecond census query (`SELECT event_id, count() GROUP BY event_id`) tells you which patterns are even possible, deterministically, faster and more reliably than semantic similarity.

**What you keep:** Qdrant + embeddings for the analyst chat (semantic search over case events is valuable for natural-language queries). The `rag_embed_high_severity_events` task is good — keep it for chat, not for pattern selection.

### 3. DeepSeek-R1 as a dependency

**Why:** Slow inference, unreliable structured output, eats VRAM alongside your primary model. You're already running Qwen2.5-14B as your default `OLLAMA_MODEL`. Use one model for everything.

---

## What I'd Change

### 1. Consolidate to ONE pattern detection system

Merge System 2 (59 rule-based patterns) and System 3 (synced external patterns) into a single pipeline:

```
Pattern Sources:                      Unified Pipeline:
┌──────────────────┐
│ pattern_rules.py │──┐
│ (59 built-in)    │  │    ┌─────────────┐    ┌──────────────┐    ┌────────────────┐
└──────────────────┘  ├───→│ Census Filter│───→│ Run Matching │───→│ Score & Store  │
┌──────────────────┐  │    │ (skip if no  │    │ Queries      │    │ (unified       │
│ AttackPattern DB │──┘    │  event_ids)  │    │              │    │  confidence)   │
│ (OpenCTI, Sigma, │       └─────────────┘    └──────────────┘    └────────────────┘
│  MITRE, Hayabusa)│
└──────────────────┘
```

The `AttackPattern` model in `models/rag.py` already has a `clickhouse_query` field. Your built-in 59 patterns from `pattern_rules.py` should be loaded into the same `AttackPattern` table at startup (or via migration). One table, one detection loop, one confidence scorer.

**Census filter (new, ~20 lines):**
```sql
SELECT event_id, count() as cnt
FROM events
WHERE case_id = {case_id:UInt32}
  AND (noise_matched = false OR noise_matched IS NULL)
GROUP BY event_id
```

Before running any pattern, check if its `required_event_ids` exist in the census. No 4662 events? Skip every DCSync pattern. No 4768/4769? Skip all Kerberos patterns. On a typical case, this eliminates 40-70% of queries. On edge cases (e.g., a case with only firewall logs), it eliminates 90%+.

### 2. Restructure CaseAnalyzer with parallel execution and AI checkpoints

**Current flow (sequential, ~8 phases, no decisions):**
```
Profile → Cluster → Gap Detect → Hayabusa → Patterns → OpenCTI → Actions → Finalize
```

**New flow (parallel where possible, AI at decision points):**

```
Phase 0: Census (ClickHouse, <1 sec)
    ↓
Phase 1 (parallel Celery tasks):
    ├── Per-host behavioral profiling + peer clustering
    ├── Gap detection (brute force, spraying, behavioral anomaly)
    └── Hayabusa correlation + attack chain building
    ↓
Phase 2: Pattern Detection (filtered by census)
    Run unified pattern queries against ClickHouse
    Score with unified confidence calculator
    ↓
★ AI Checkpoint 1: Triage & Prioritize (1 LLM call)
    Input: Census stats, gap findings, pattern matches, attack chains
    Output: JSON with priority_findings[], investigation_threads[], skip_patterns[]
    ↓
Phase 3: IOC Pivot & Timeline (new — see below)
    For each IOC in the case: find matching events, get surrounding context,
    build causal chains
    ↓
Phase 4: Enrichment
    OpenCTI lookups for IOCs and findings
    ↓
★ AI Checkpoint 2: Synthesis (1 LLM call)
    Input: All findings, IOC timelines, enrichment results
    Output: Executive narrative, recommended actions, confidence assessment
    ↓
Phase 5: Finalize
    Store results, generate suggested actions
```

Total AI calls in the pipeline: **2**. Each is a single well-structured prompt with clear JSON output expectations. On the A2, each takes 15-30 seconds. Total AI overhead: under 1 minute.

**Parallelization via Celery:**

Your Celery infrastructure already exists. The key change is splitting Phase 1 into subtasks:

```python
from celery import chord

# Phase 1: parallel per-host analysis
subtasks = []
for host in hosts_from_census:
    subtasks.append(analyze_host.s(case_id, host))

# Also run gap detection in parallel
subtasks.append(run_gap_detection.s(case_id))
subtasks.append(run_hayabusa_correlation.s(case_id))

# Phase 2 runs after all Phase 1 tasks complete
callback = run_pattern_detection.s(case_id)
chord(subtasks)(callback)
```

This is the biggest performance win for large cases. A 40M artifact case with 50 hosts currently processes all hosts sequentially. With chord, they run in parallel (limited by your Celery worker count).

### 3. Single model: Qwen2.5-14B-Instruct (or Qwen3-8B)

You're already running Qwen2.5-14B as `Config.OLLAMA_MODEL`. Make it the only model:

- **Drop** the `DEEPSEEK_MODEL` constant from `ai_correlation_analyzer.py`
- **Use** temperature 0.1 for structured output (checkpoints, tool calls)
- **Use** temperature 0.3 for analysis (event review, pattern reasoning)
- **Use** temperature 0.5 for narrative generation (reports, summaries)

If you find Qwen2.5-14B too slow on the A2 for the chat use case (where users expect <10s responses), consider **Qwen3-8B** — smaller, newer, fast, good tool-calling support. You could even run both: 8B always loaded for chat, 14B loaded on-demand for analysis tasks.

### 4. Upgrade the "Ask AI" to a proper tool-use chat agent

Your `/api/rag/review-events` endpoint currently stuffs events into a prompt. Redesign it as an agent loop with tools.

---

## What I'd Add

### 1. IOC-Anchored Timeline Reconstruction (Your requirement 2.3)

This is the biggest missing piece. Here's how it should work:

```
IOCs in case (from extraction or analyst input)
    ↓
For each IOC:
    1. Query ClickHouse for ALL events containing this IOC
       (IP in src_ip/dst_ip, hash in file_hash fields,
        domain in dns_query, hostname in source_host/target_host)
    2. For each matching event, get surrounding context:
       Same host ±15 minutes, same user ±30 minutes
    3. Tag events with IOC association
    ↓
Build temporal chains:
    - Group IOC-associated events by host
    - Order chronologically
    - Identify causal sequences (e.g., DNS lookup → connection → process spawn)
    - Link cross-host activity (IOC appears on host A, then host B)
    ↓
Store as TimelineEntry objects:
    - Each entry: timestamp, host, user, event summary, IOCs involved,
      preceding_entry_id, following_entry_id
    - Cross-host links: lateral_movement_from, lateral_movement_to
    ↓
AI narrates the timeline (1 LLM call):
    Input: Structured timeline entries
    Output: "At 09:14, the attacker used compromised credentials to
             authenticate to HOST-A (IOC: 192.168.1.50). Within 3 minutes,
             PowerShell was executed to download a payload from
             evil.example.com (IOC: matching domain)..."
```

**Implementation:** New file `utils/ioc_timeline_builder.py`. Queries ClickHouse with IOC values, builds the chain, stores in a new `IOCTimelineEntry` model. Runs as Phase 3 in the redesigned pipeline.

Key ClickHouse query for IOC pivoting:
```sql
-- Find all events matching any IOC value
SELECT *
FROM events
WHERE case_id = {case_id:UInt32}
  AND (
    src_ip IN ({ioc_ips:Array(String)})
    OR dst_ip IN ({ioc_ips:Array(String)})
    OR domain IN ({ioc_domains:Array(String)})
    OR file_hash_md5 IN ({ioc_hashes:Array(String)})
    OR file_hash_sha256 IN ({ioc_hashes:Array(String)})
    OR hasAny(ioc_values, {all_iocs:Array(String)})
  )
ORDER BY timestamp_utc
```

Then for surrounding context:
```sql
-- Get events ±15 min on same host
SELECT *
FROM events
WHERE case_id = {case_id:UInt32}
  AND source_host = {host:String}
  AND timestamp_utc BETWEEN {start:DateTime64} AND {end:DateTime64}
  AND (noise_matched = false OR noise_matched IS NULL)
ORDER BY timestamp_utc
LIMIT 200
```

### 2. Analyst Chat Agent with Tool Use (Your requirement 3)

This is where agentic AI earns its keep. Not in the batch pipeline (where deterministic code is faster and more reliable), but in the interactive investigation where an analyst needs to explore.

**Architecture:**

```
Analyst types question
    ↓
WebSocket / SSE connection
    ↓
Agent receives: system prompt + case context summary + conversation history + user question
    ↓
Agent reasons and decides which tool to call
    ↓
┌──────────────────────────────────────────────────────┐
│ Available Tools:                                      │
│                                                       │
│ query_events(filters, time_range, limit)              │
│   → Runs parameterized ClickHouse query               │
│                                                       │
│ get_user_profile(username)                            │
│   → Returns behavioral profile + anomaly flags        │
│                                                       │
│ get_host_profile(hostname)                            │
│   → Returns system profile + anomaly flags            │
│                                                       │
│ search_events(natural_language_query)                 │
│   → Semantic search over embedded high-severity events│
│                                                       │
│ get_findings(case_id, severity?, category?)           │
│   → Returns pattern matches, gap findings, chains     │
│                                                       │
│ lookup_ioc(value)                                     │
│   → Checks OpenCTI + local IOC database               │
│                                                       │
│ get_timeline(host?, user?, time_range?)               │
│   → Returns IOC-anchored timeline entries              │
│                                                       │
│ get_hayabusa_detections(host?, min_level?)            │
│   → Returns Sigma/Hayabusa rule matches               │
│                                                       │
│ count_events(event_id?, host?, user?, time_range?)    │
│   → Quick ClickHouse COUNT for filtering questions     │
│                                                       │
│ tag_event(record_id, tag, note)                       │
│   → Marks an event as analyst-tagged with note         │
│                                                       │
└──────────────────────────────────────────────────────┘
    ↓
Tool result returned to agent
    ↓
Agent reasons about result, may call another tool or respond
    ↓
Response streamed back to analyst
```

**Key design decisions for the A2:**

- **Max 3-5 tool calls per question.** Hard limit to prevent runaway loops on slow hardware. After 5 tools calls, the agent must synthesize and respond.
- **Pre-loaded case context.** On chat open, load and cache: case summary stats (from census), top 10 findings, IOC list, affected hosts/users. Include this in every system prompt so the agent doesn't need a tool call for basic questions.
- **Streaming responses.** Use Ollama's streaming API (`"stream": true`). The analyst sees tokens as they generate, which masks the A2's slower inference. Your existing `review-events` endpoint already has the Flask `stream_with_context` pattern.
- **Tool call format.** Use Qwen2.5's native function-calling format. It's trained on this and produces reliable structured output. The system prompt defines tools as JSON schemas, the model outputs `<tool_call>` blocks, your backend parses and executes them.

**Implementation:** New file `utils/chat_agent.py` with the agent loop. New WebSocket route (or SSE endpoint) in `routes/chat.py`. The tools are thin wrappers around your existing utility functions — the code already exists, it just needs to be exposed as callable tools.

**Example conversation flow:**

```
Analyst: "What happened on WORKSTATION-7 between 2 and 4 PM yesterday?"

Agent thinks: I need events for that host and time range.
Agent calls: query_events(host="WORKSTATION-7", time_range="2025-02-06 14:00 to 16:00", limit=100)
Tool returns: 47 events, including 3 high-severity Hayabusa detections...

Agent thinks: I see suspicious PowerShell. Let me check what the user was doing.
Agent calls: get_user_profile("jsmith")
Tool returns: jsmith behavioral profile, off-hours activity flagged as anomalous...

Agent responds: "Between 2:00 and 4:00 PM on WORKSTATION-7, I found 47 events including
3 high-severity detections. At 14:23, user jsmith executed PowerShell with an encoded
command [Event 4688, Hayabusa rule: 'Suspicious Encoded PowerShell']. This user's
profile shows off-hours activity is 340% above their peer group baseline. At 14:25,
a network connection was made to 203.0.113.45 which matches IOC..."

Analyst: "Is that IP in any other events?"

Agent calls: query_events(filters={dst_ip: "203.0.113.45"})
Tool returns: 12 events across 3 hosts...

Agent responds: "Yes — 203.0.113.45 appears in 12 events across 3 hosts:
WORKSTATION-7 (6 events), SERVER-DC01 (4 events), and WORKSTATION-12 (2 events).
The earliest appearance was on SERVER-DC01 at 09:14, suggesting lateral movement
from the domain controller outward..."
```

This is the investigation flow that currently requires an analyst to manually query ClickHouse, cross-reference findings, and mentally build the picture. The agent does it in seconds.

### 3. Census-Based Pre-Filter (Biggest Bang for Buck)

Already described above, but to be explicit — this is the single change with the highest impact-to-effort ratio. Add this method to `CaseAnalyzer`:

```python
def _run_census(self) -> Dict[str, int]:
    """Get event_id distribution for the case. Used to skip impossible patterns."""
    client = get_fresh_client()
    result = client.query(
        "SELECT event_id, count() as cnt FROM events "
        "WHERE case_id = {case_id:UInt32} "
        "AND (noise_matched = false OR noise_matched IS NULL) "
        "GROUP BY event_id",
        parameters={'case_id': self.case_id}
    )
    return {row[0]: row[1] for row in result.result_rows}
```

Then before each pattern query:
```python
def _should_run_pattern(self, pattern, census):
    """Check if pattern's required events exist in this case."""
    required = pattern.get('required_event_ids', [])
    if not required:
        return True  # No requirements specified, run it
    return any(eid in census for eid in required)
```

20 lines of code. Saves minutes on large cases.

### 4. Cross-Host Pattern Detection (Your requirement 2.2)

Your current gap detectors look for brute force and password spraying, but the password spraying detector specifically looks at single-source attacks. You mentioned "this may be across many machines not just one."

Add a cross-host correlation step after individual pattern detection:

```sql
-- Distributed brute force: same username failing across many hosts
SELECT
    username,
    count() as total_failures,
    uniqExact(source_host) as target_hosts,
    min(timestamp_utc) as first_fail,
    max(timestamp_utc) as last_fail,
    dateDiff('second', min(timestamp_utc), max(timestamp_utc)) as duration_secs,
    groupArray(DISTINCT source_host) as host_list
FROM events
WHERE case_id = {case_id:UInt32}
  AND event_id = '4625'
  AND (noise_matched = false OR noise_matched IS NULL)
GROUP BY username
HAVING total_failures >= 10 AND target_hosts >= 3
ORDER BY total_failures DESC
```

```sql
-- Password spray across the network: one source hitting many users on many hosts
SELECT
    src_ip,
    count() as total_failures,
    uniqExact(username) as unique_users,
    uniqExact(source_host) as target_hosts,
    min(timestamp_utc) as first_fail,
    max(timestamp_utc) as last_fail,
    groupArray(DISTINCT source_host) as host_list
FROM events
WHERE case_id = {case_id:UInt32}
  AND event_id = '4625'
  AND src_ip != ''
  AND (noise_matched = false OR noise_matched IS NULL)
GROUP BY src_ip
HAVING unique_users >= 5 AND target_hosts >= 2
ORDER BY total_failures DESC
```

These should be added to `pattern_rules.py` as cross-host temporal patterns. They're ClickHouse queries, not AI — fast and deterministic.

---

## Recommended Model Strategy for 16GB GPU

### Primary: Qwen2.5-14B-Instruct (Q5_K_M quantization)

- ~10-11GB VRAM with Q5_K_M
- Good function-calling / structured output
- Reliable JSON generation
- You already have it configured and tested
- ~15-30 tokens/sec on A2 depending on context length

### Alternative: Qwen3-8B (Q5_K_M or Q6_K)

- ~6-7GB VRAM, leaving room for embeddings + overhead
- Faster inference (~25-45 tokens/sec on A2)
- Strong tool-use capability (newer model)
- Better for the chat agent where response latency matters
- Trade-off: less "deep" reasoning than 14B

### My recommendation: Start with Qwen2.5-14B for everything

One model, always loaded, no swapping. If chat latency becomes a problem on the A2, switch the chat agent to Qwen3-8B while keeping the 14B for batch analysis.

### Embedding model: Keep all-MiniLM-L6-v2

It's tiny (~90MB), fast, and 384 dimensions is efficient for Qdrant. No reason to change it.

---

## Implementation Priority

### Week 1-2: Census filter + Pattern consolidation

1. Add `_run_census()` to CaseAnalyzer (~20 lines)
2. Migrate 59 patterns from `pattern_rules.py` into `AttackPattern` table
3. Unify the detection loop to use one table, one confidence scorer
4. Add cross-host brute force / spray patterns
5. Remove `ai_correlation_analyzer.py` dependency from main pipeline
6. Drop DeepSeek-R1, use Qwen2.5-14B everywhere

**Measurable outcome:** Case analysis 40-70% faster due to census filtering. One pattern system instead of three.

### Week 3-4: Parallel execution + IOC timeline

1. Split CaseAnalyzer Phase 1 into per-host Celery subtasks
2. Add `chord` callback for Phase 2
3. Build `ioc_timeline_builder.py` — IOC pivot → context fetch → chain building
4. Add AI Checkpoint 1 (triage) and Checkpoint 2 (synthesis)

**Measurable outcome:** 40M artifact cases complete in minutes instead of tens of minutes. IOC timelines generate automatically.

### Week 5-8: Chat agent with tools

1. Define tool schemas (wrappers around existing utility functions)
2. Build agent loop in `utils/chat_agent.py`
3. Add SSE endpoint in `routes/chat.py`
4. Implement case context pre-loading
5. Add tool call parsing and execution
6. Frontend: chat UI with streaming responses

**Measurable outcome:** Analysts can ask questions and get investigated answers, not just "here's what 150 events look like."

### Ongoing: Refinement

- Tune tool call limits based on A2 performance
- Add more tools as analysts request them (e.g., "compare this host to its peer group")
- Consider Qwen3-8B if chat latency is too high
- When you upgrade GPU, expand agent capabilities (more tool calls, larger context windows)

---

## Summary: What Changes

| Component | Current | Proposed |
|-----------|---------|----------|
| **Models** | DeepSeek-R1 14B + Qwen2.5 14B | Qwen2.5-14B only (or Qwen3-8B for chat) |
| **Pattern detection** | 3 separate systems (3+59+dynamic patterns) | 1 unified system (59+ patterns in AttackPattern table) |
| **Pattern filtering** | Run everything | Census-based: skip impossible patterns |
| **Execution** | 8 sequential phases | Parallel per-host + 2 AI checkpoints |
| **AI role in pipeline** | Validates pre-extracted candidates | Triages findings + synthesizes narrative |
| **IOC → Timeline** | Doesn't exist as coherent pipeline | IOC pivot → context fetch → causal chains → AI narrative |
| **Analyst chat** | Event dump → single LLM response | Tool-use agent: query, profile, search, tag |
| **Cross-host detection** | Single-source patterns only | Multi-host brute force, distributed spray |

The core principle: **your deterministic code is excellent — keep it doing the heavy lifting.** AI sits at two places: (1) decision checkpoints in the batch pipeline where it triages and synthesizes, and (2) the interactive chat where it drives investigation with tools. Everything else stays fast, reliable ClickHouse queries and well-crafted forensic logic.



does your plan account for licensing? The company taht uses the software can use a free version with opencti integration and no AI or they can license it and get both - would it require AI? its fine if it does one more reason to license it

6:53 PM

Examined licensing tiers and verified AI requirement aligns with monetization strategy



Good question. Let me check your existing mode system since I remember it handles this already.


Reconciled architecture with licensing tiers; core improvements work free, AI enhances paid






Your mode system is well-built. And yes — my plan maps cleanly onto it. Here's how it breaks down:

Everything that runs without AI (Modes A and C — free tier):

Census-based pattern filtering — pure SQL, no AI
Unified pattern detection (all 59+ patterns) — ClickHouse queries, deterministic confidence scoring
Cross-host brute force / password spray detection — SQL aggregations
Parallel per-host Celery execution — infrastructure change, no AI
Behavioral profiling, peer clustering, gap detection — already Mode A compatible
Hayabusa correlation + attack chain building — already Mode A compatible
IOC-anchored timeline data gathering — the ClickHouse pivot queries that find IOC-matching events and surrounding context are pure SQL. The timeline structure gets built deterministically
IOC extraction with regex fallback — already works this way
What AI adds (Modes B and D — licensed):

AI Checkpoint 1: Triage & prioritize findings (instead of just dumping all 59 pattern results at the analyst, the AI ranks what matters and identifies investigation threads)
AI Checkpoint 2: Synthesis narrative ("here's what happened" instead of a table of findings)
IOC timeline narration — the AI turns the structured timeline entries into a readable incident story
AI-first IOC extraction from EDR reports (better extraction before regex catch)
The chat agent — this is the killer feature gap between free and licensed. Free users see findings as tables and must manually investigate. Licensed users ask questions and the agent investigates for them with tools
Your existing FeatureAvailability class and AnalysisModeContext handle this perfectly. The redesigned pipeline would look like:

python
with AnalysisModeContext() as ctx:
    # Always runs (all modes)
    census = self._run_census()
    findings = self._run_pattern_detection(census)  # unified, filtered
    ioc_timeline = self._build_ioc_timeline()       # structural, SQL-based
    
    # Licensed only
    if ctx.has_ai:
        prioritized = self._ai_triage(findings, ioc_timeline)    # Checkpoint 1
        narrative = self._ai_synthesize(prioritized)              # Checkpoint 2
    else:
        prioritized = self._rule_based_sort(findings)  # Sort by confidence score
        narrative = None  # No AI summary
    
    if ctx.has_opencti:
        self._enrich_with_opencti(prioritized)
The free tier actually gets significantly better under my plan — census filtering, consolidated patterns, parallelization, cross-host detection, and IOC timeline structures are all improvements that don't touch AI. That's a better free product, which makes the upgrade path more compelling because the licensed user sees the same solid data plus AI intelligence on top.

The chat agent is the clearest licensing differentiator. Free users get a dashboard of findings. Licensed users get an investigator they can talk to. That's a tangible "this saves me hours per case" value proposition.

One thing to decide: do you want the IOC timeline narrative in the free tier? Right now I have it as AI-only, but you could generate a basic template-driven timeline summary without AI (e.g., "At 09:14, IOC 192.168.1.50 was observed on HOST-A in event 4624. At 09:17, the same IOC appeared on HOST-B..."). It would be factual but dry. The AI version would be the polished incident story. That's another nice free-vs-licensed contrast. <--- timeline would be AI required feature


The headline: Your deterministic forensic code is genuinely strong. The AI is underutilized and misplaced. You have three pattern detection systems that should be one. The biggest wins aren't "more AI" — they're a 20-line census filter, Celery parallelization you already have the infrastructure for, and consolidating to a single model.
The three things that will make the most immediate difference:

Census filter before pattern detection — one ClickHouse GROUP BY event_id query tells you which of your 59+ patterns are even possible. Eliminates 40-70% of queries. 20 lines of code.
Kill the three-system pattern sprawl — merge pattern_rules.py (59 good patterns), pattern_event_mappings.py (3 AI-validated patterns), and the RAG AttackPattern table into one unified pipeline with one confidence scorer. Right now an analyst can't reason about findings because three systems report differently.
Drop DeepSeek-R1, standardize on Qwen2.5-14B — you're already running it as your default model. R1 is too slow on the A2 for interactive work, and your fallback parsing code proves its structured output is unreliable. One model, always loaded, no VRAM swapping.

The thing you're actually missing: IOC-anchored timeline reconstruction. You have IOC extraction, you have timeline generation, but nothing that starts from an IOC, pivots through ClickHouse to find every event containing it, grabs the surrounding context, and builds a causal chain across hosts. That's your requirement 2.3, and it's the feature that will most change how analysts work.
The chat agent is where agentic AI actually earns its keep — not in the batch pipeline (where your ClickHouse queries are faster and more reliable), but in interactive investigation where the analyst asks a question and the agent calls tools to query events, check profiles, look up IOCs, and follow threads. Your /api/rag/review-events is the foundation, it just needs tools instead of prompt-stuffing.