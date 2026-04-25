# CaseScope — OpenCTI Integration Plan

## Overview

This plan maps every system in CaseScope where OpenCTI threat intelligence can add value, whether the system operates standalone or downstream of the case analyzer. For each system, the document covers its current pipeline, what OpenCTI data is already available vs. what needs fetching, and the specific injection points.

The guiding principle: **CaseScope already fetches rich OpenCTI data but barely uses it where it matters most — at the moment AI generates text or an analyst makes a decision.** Every integration below connects existing data to existing consumers. No new ML dependencies, no GPU requirements, no new infrastructure.

---

## System Map

There are seven distinct execution paths in CaseScope where OpenCTI context can improve output. Three run through the case analyzer. Four are standalone. They share a common data source (`OpenCTIContextProvider`) and cache layer (`OpenCTICache`), but each has different injection requirements.

```
┌─────────────────────────────────────────────────────────────┐
│                     CASE ANALYZER PIPELINE                  │
│                                                             │
│  Phase 5: Pattern Analysis ──► Phase 7: AI Triage           │
│  Phase 6: IOC Timeline     ──► Phase 8: OpenCTI Enrichment  │
│                             ──► Phase 9: AI Synthesis ◄──── │ ← GAP: enrichment
│                             ──► Phase 10: Suggested Actions  │   data never reaches
│                                                             │   synthesis prompt
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    STANDALONE PIPELINES                      │
│                                                             │
│  1. AI Pattern Correlation (Hunting → AI Tab)               │
│  2. Ask AI (Hunting → AI Tab → Ask AI modal)                │
│  3. AI Report Generation (Case Reports page)                │
│  4. AI Timeline Generation (Case Reports page)              │
│  5. Chat Agent (streaming chat, any context)                │
│                                                             │
│  None of these call OpenCTIContextProvider today.            │
└─────────────────────────────────────────────────────────────┘
```

---

## A. Case Analyzer Pipeline (Modes C and D)

The case analyzer is the only system that currently uses OpenCTI, but the data it fetches dies on the vine — it gets attached to findings but never reaches the AI prompts that generate the synthesis narrative or suggested actions.

### A1. Phase 9: AI Synthesis Checkpoint

**File:** `utils/ai_checkpoints.py` → `SynthesisCheckpoint._build_prompt()`

**Current state:** The synthesis prompt assembles sections from triage results, gap findings, pattern results, attack chains, IOC timeline, and profiling stats. OpenCTI enrichment runs in Phase 8, one phase earlier, and attaches `opencti_context` to every finding in `_all_findings`. But when `_run_ai_synthesis()` builds its context dict (line ~908), it passes `pattern_results` and `attack_chains` — it never extracts the `opencti_context` that Phase 8 just attached.

**Integration:**

In `case_analyzer.py` → `_run_ai_synthesis()`, add `opencti_context` to the context dict passed to the synthesis checkpoint:

```python
# After Phase 8 enrichment has run, extract the aggregated context
opencti_data = {}
if self.mode in ['C', 'D']:
    # Findings already have opencti_context attached from Phase 8
    # Extract unique threat actors, campaigns, technique context
    for finding in self._all_findings:
        ctx = getattr(finding, 'opencti_context', None) or (
            finding.get('opencti_context') if isinstance(finding, dict) else None
        )
        if ctx and ctx.get('available'):
            opencti_data = ctx
            break  # Same aggregated context on all findings

context = {
    'triage': self._triage_result,
    'gap_findings': self._gap_findings,
    'pattern_results': self._pattern_results,
    'attack_chains': self._attack_chains,
    'ioc_timeline': self._ioc_timeline,
    'profiling_stats': self._profiling_stats,
    'opencti_context': opencti_data,  # NEW
}
```

In `SynthesisCheckpoint._build_prompt()`, add a threat intel section:

```python
opencti = context.get('opencti_context', {})
if opencti.get('available'):
    ti_lines = []
    # Threat actors
    actors = opencti.get('threat_actors', [])
    if actors:
        actor_names = [a['name'] for a in actors[:5]]
        ti_lines.append(f"Associated threat actors: {', '.join(actor_names)}")
    # Campaigns
    campaigns = opencti.get('campaigns', [])
    if campaigns:
        for c in campaigns[:3]:
            ti_lines.append(f"Campaign: {c.get('name')} ({c.get('published', 'date unknown')})")
    # Enriched IOCs
    enriched = opencti.get('ioc_enrichment', {})
    if enriched:
        ti_lines.append(f"{len(enriched)} IOCs found in threat intelligence with scoring")
    if ti_lines:
        sections.append("THREAT INTELLIGENCE (from OpenCTI):\n" + "\n".join(ti_lines))
```

**Effort:** Small. The data is already computed; this is plumbing.

**Impact:** The synthesis executive summary can now reference specific threat groups and campaigns instead of producing generic narratives.

### A2. Phase 10: Suggested Actions

**File:** `utils/case_analyzer.py` → `_generate_suggested_actions()`

**Current state:** Suggested actions are generated from confidence thresholds and entity identification. If confidence >= 75 and an entity is identified, suggest marking it compromised. If IOCs are found, suggest adding them. Generic rules.

**Integration:** Use OpenCTI's intrusion set → TTP relationships to suggest *what to hunt for next*. The `opencti_context` on findings contains `techniques` with their associated threat actors. For each detected technique, look up which other techniques those same actors use and generate "Hunt for [technique name] on [compromised hosts]" suggestions.

This is a graph traversal, not an AI call:

```python
# In _generate_suggested_actions, after existing logic:
if self.mode in ['C', 'D']:
    detected_techniques = set()
    for finding in all_findings:
        ctx = getattr(finding, 'opencti_context', None)
        if ctx and ctx.get('techniques'):
            detected_techniques.update(ctx['techniques'].keys())

    # Get co-occurring techniques from threat actors
    for actor in opencti_data.get('threat_actors', []):
        actor_techniques = {t['mitre_id'] for t in actor.get('attack_patterns', [])}
        # Techniques this actor uses that we HAVEN'T detected yet
        missing = actor_techniques - detected_techniques
        for tech_id in list(missing)[:3]:
            actions.append(SuggestedAction(
                action_type='hunt',
                description=f"Hunt for {tech_id} — used by {actor['name']} alongside detected techniques",
                priority='high',
                rationale=f"Threat actor {actor['name']} is known to use {tech_id} in conjunction with techniques already detected in this case"
            ))
```

**Effort:** Medium. Requires understanding the SuggestedAction model and testing with real OpenCTI data.

**Impact:** Transforms generic "investigate this host" suggestions into targeted "hunt for T1021 lateral movement because APT29 chains it after the credential dumping we detected."

---

## B. AI Pattern Correlation (Standalone — Hunting Tab)

**Trigger:** User clicks "AI Pattern Matching" on the Hunting → AI tab

**Path:** `tab_ai_hunting.html` → `startAICorrelation()` → `/api/rag/ai-correlation/start` → `rag_tasks.ai_pattern_correlation` → `CandidateExtractor` → `DeterministicEvidenceEngine` → `AICorrelationAnalyzer.analyze_with_evidence()`

**Current state:** The AI correlation pipeline runs completely independently of the case analyzer. It extracts candidates, runs deterministic evidence checks, then asks an LLM to adjust confidence within [-20, +10]. The LLM prompt contains the evidence package, check results, coverage data, burst analysis, and pattern-specific hardcoded guidance. No threat intelligence.

**What OpenCTI data is NOT already available:** This pipeline never calls `OpenCTIContextProvider`. Unlike the case analyzer (which enriches in Phase 8), the correlation task in `rag_tasks.py` has no OpenCTI touchpoint.

**Integration — Option A (per-pattern enrichment in the task):**

In `rag_tasks.ai_pattern_correlation`, after initializing the `ai_analyzer`, create an `OpenCTIContextProvider` instance:

```python
# In the task, after ai_analyzer initialization:
from utils.opencti_context import OpenCTIContextProvider
opencti_provider = OpenCTIContextProvider(case_id, analysis_id)
opencti_available = opencti_provider.is_available()
```

Then in the per-pattern loop, before calling `ai_analyzer.analyze_with_evidence()`, fetch technique context:

```python
threat_intel_context = ""
if opencti_available:
    mitre_ids = pattern_config.get('mitre_techniques', [])
    for mid in mitre_ids[:2]:
        ctx = opencti_provider.get_attack_pattern_context(mid)
        if ctx.get('technique_name'):
            actors = [a['name'] for a in ctx.get('threat_actors', [])[:3]]
            if actors:
                threat_intel_context += f"\nTHREAT INTEL: {mid} is used by {', '.join(actors)}."
            if ctx.get('detection_guidance'):
                threat_intel_context += f"\nDetection guidance: {ctx['detection_guidance'][:200]}"
```

**Integration — Option B (inject into the prompt in `ai_correlation_analyzer.py`):**

Modify `analyze_with_evidence()` to accept an optional `threat_intel_context` string parameter and append it to the prompt before the guidance section. This keeps the OpenCTI plumbing in the task and the prompt construction in the analyzer.

The prompt already ends with pattern-specific guidance blocks (PTH, LSASS, DCSync, etc.). Add the threat intel block just before those:

```python
if threat_intel_context:
    prompt += f"\n{threat_intel_context}\n"
```

**Where it appears in the UI:** The results table in the AI Hunting tab currently shows: Pattern, Category, Severity, AI Confidence, Reasoning, IOCs Found, Events, Time Frame. The `ai_reasoning` field returned from the LLM will now naturally reference threat actors and campaigns because the prompt included that context. No UI changes needed for the reasoning column.

Optional enhancement: add a "Threat Intel" badge/column to the results table. This would require the task to return threat actor names in the result dict and the frontend to render them.

**Effort:** Medium. The task needs an OpenCTI provider, and the analyzer needs to accept the extra context. The cache layer means repeated technique lookups (same MITRE ID across patterns) are cheap.

**Impact:** The LLM's confidence adjustment becomes more informed. A borderline Pass-the-Hash detection gets a different treatment when the LLM knows APT28 is actively using that technique chain versus a technique that hasn't been seen in recent campaigns.

---

## C. Ask AI (Standalone — Hunting Tab)

**Trigger:** User clicks "Ask AI" button, types a question, submits

**Path:** `tab_ai_hunting.html` → `submitAskAI()` → `/api/rag/ask` → RAG context building (6 steps) → LLM query

**Current state:** The `/api/rag/ask` endpoint in `routes/rag.py` builds context from: (1) RAG vector search for relevant attack patterns, (2) high-severity events, (3) specialized queries keyed on question keywords, (4) related events from search terms, (5) case summary stats, (6) pattern match results. No OpenCTI.

**What's interesting:** This endpoint already does keyword detection on the question (brute force, lateral movement, credential theft, etc.) to run specialized ClickHouse queries. This same mechanism can trigger OpenCTI lookups.

**Integration — Three injection points:**

**C1. Threat intel context after pattern matches (step 6.5):**

After loading `PatternRuleMatch` results (around line 1660), collect MITRE technique IDs from those matches and add a threat intel section:

```python
# After step 6 (pattern matches), add step 6.5:
try:
    from utils.opencti_context import OpenCTIContextProvider
    provider = OpenCTIContextProvider(case_id)
    if provider.is_available() and pattern_matches:
        all_techniques = set()
        for pm in pattern_matches:
            if pm.mitre_techniques:
                all_techniques.update(pm.mitre_techniques)

        if all_techniques:
            actors = provider.get_threat_actor_context(list(all_techniques))
            if actors:
                context_parts.append(f"\nTHREAT INTELLIGENCE (OpenCTI):")
                for actor in actors[:5]:
                    techniques = [t['mitre_id'] for t in actor.get('attack_patterns', [])
                                  if t.get('mitre_id') in all_techniques]
                    context_parts.append(
                        f"  Threat Actor: {actor['name']} — "
                        f"uses detected techniques: {', '.join(techniques)}"
                    )
except Exception as e:
    logger.debug(f"[Ask AI] OpenCTI enrichment skipped: {e}")
```

**C2. IOC enrichment when question contains IOC-shaped values:**

Add IOC detection similar to the existing keyword matching:

```python
# Detect IOC-shaped values in the question
import re
ip_match = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', question)
hash_match = re.findall(r'\b[a-fA-F0-9]{32,64}\b', question)
domain_match = re.findall(r'\b[\w.-]+\.\w{2,}\b', question)

ioc_candidates = ip_match + hash_match
if ioc_candidates and provider.is_available():
    for ioc_val in ioc_candidates[:3]:
        enrichment = provider.enrich_ioc(ioc_val, 'Unknown')
        if enrichment.get('found'):
            context_parts.append(
                f"\nOPENCTI IOC: {ioc_val} — Score: {enrichment.get('score', 'N/A')}, "
                f"Labels: {', '.join(enrichment.get('labels', []))}"
            )
```

**C3. Campaign context for attribution questions:**

When the question contains attribution-related keywords ("who", "threat actor", "APT", "group", "campaign", "attribution"), pull campaign context:

```python
attribution_keywords = ['who', 'threat actor', 'apt', 'group', 'campaign', 'attribution', 'nation state']
if any(kw in question_lower for kw in attribution_keywords) and provider.is_available():
    techniques = list(all_techniques) if all_techniques else []
    if techniques:
        campaigns = provider.get_campaign_context(techniques, days_back=180)
        if campaigns:
            context_parts.append(f"\nRECENT CAMPAIGNS (OpenCTI, last 180 days):")
            for c in campaigns[:3]:
                context_parts.append(f"  {c.get('name')} — {c.get('description', '')[:150]}")
```

**Context window budget:** The existing endpoint caps context at `RAG_MAX_CONTEXT_CHARS` (default 12,000). OpenCTI context should be limited to ~1,000 characters to avoid crowding out event data, which is the primary value for most questions.

**Effort:** Medium. Three small additions to an existing endpoint. The main risk is context bloat — be disciplined about character limits.

**Impact:** The analyst can ask "what threat groups match our findings?" or "is this IP known?" and get grounded answers instead of the LLM guessing.

---

## D. AI Report Generation (Standalone — Case Reports Page)

**Trigger:** User clicks "Generate AI Report" from the case reports page

**Path:** `/api/reports/generate-ai/<case_uuid>` → `AIReportGenerator.__init__()` → `generate_executive_summary()`, `generate_timeline()`, `generate_ioc_list()`, `generate_summary_what/why/how()` → `_generate_word_document()`

**Current state:** The report generator builds context from three sources via `_get_incident_context()`: analyst attack narrative, EDR report, and tagged events. No threat intelligence. No connection to case analyzer results.

**This is the highest-impact integration point.** Every generated report goes to a client. The difference between "the attacker used Pass-the-Hash" and "the attacker used Pass-the-Hash, a technique actively attributed to APT29 and Wizard Spider, consistent with 3 campaigns reported in the last 90 days" is the difference between a generic and an authoritative report.

**What OpenCTI data is NOT already available:** This pipeline is completely standalone from the case analyzer. Even if the user ran a full Mode D analysis before generating a report, the report generator doesn't read those results. It builds its own context fresh.

**Integration approach — add a `_get_threat_intel_context()` method:**

```python
def _get_threat_intel_context(self, max_chars: int = 1500) -> str:
    """Get OpenCTI threat intelligence context for AI prompts.

    Collects MITRE techniques from:
    1. Case analysis results (if available)
    2. IOCs already loaded for the report
    Then queries OpenCTI for actor/campaign attribution.
    """
    from utils.opencti_context import OpenCTIContextProvider

    provider = OpenCTIContextProvider(self.case.id)
    if not provider.is_available():
        return ""

    # Collect techniques from analysis results
    techniques = set()
    try:
        from models.rag import AIAnalysisResult, PatternRuleMatch
        # From AI correlation results
        ai_results = AIAnalysisResult.query.filter_by(
            case_id=self.case.id
        ).filter(AIAnalysisResult.final_confidence >= 50).all()
        for r in ai_results:
            config = r.evidence_package or {}
            for t in config.get('mitre_techniques', []):
                techniques.add(t)

        # From pattern rule matches
        pattern_matches = PatternRuleMatch.query.filter_by(
            case_id=self.case.id
        ).filter(PatternRuleMatch.confidence >= 50).all()
        for pm in pattern_matches:
            if pm.mitre_techniques:
                techniques.update(pm.mitre_techniques)
    except Exception:
        pass

    if not techniques:
        return ""

    sections = []

    # Get threat actors
    actors = provider.get_threat_actor_context(list(techniques))
    if actors:
        actor_lines = []
        for a in actors[:5]:
            matching = [t['mitre_id'] for t in a.get('attack_patterns', [])
                        if t.get('mitre_id') in techniques]
            actor_lines.append(f"- {a['name']}: uses {', '.join(matching)}")
        sections.append("Threat Actors (OpenCTI):\n" + "\n".join(actor_lines))

    # Get campaigns
    campaigns = provider.get_campaign_context(list(techniques), days_back=180)
    if campaigns:
        camp_lines = [f"- {c['name']} ({c.get('published', 'N/A')})" for c in campaigns[:3]]
        sections.append("Recent Campaigns:\n" + "\n".join(camp_lines))

    # Enrich report IOCs
    enriched_iocs = []
    for ioc in self.iocs[:10]:
        result = provider.enrich_ioc(ioc.value, ioc.ioc_type)
        if result.get('found'):
            enriched_iocs.append(f"- {ioc.value}: score {result.get('score')}, {', '.join(result.get('labels', []))}")
    if enriched_iocs:
        sections.append("IOC Intelligence:\n" + "\n".join(enriched_iocs))

    context = "\n\n".join(sections)
    return context[:max_chars] if len(context) > max_chars else context
```

**Injection into section prompts:**

In `generate_executive_summary()`, add threat intel to the prompt:

```python
threat_intel = self._get_threat_intel_context()
if threat_intel:
    prompt += f"\n\nTHREAT INTELLIGENCE CONTEXT:\n{threat_intel}\n"
    prompt += ("If the detected techniques align with known threat actors or campaigns, "
               "mention the attribution in the executive summary with appropriate caveats "
               "(e.g., 'consistent with TTPs attributed to...').")
```

Same pattern for `generate_summary_how()` (the techniques/methodology section) and `generate_ioc_list()` (where OpenCTI scores inform IOC prioritization).

**Effort:** Medium-high. Requires a new method, injection into 3-4 prompt builders, and testing that the added context doesn't cause the LLM to hallucinate attribution beyond what OpenCTI actually supports.

**Impact:** High. Reports become threat-intel-enriched without the analyst manually looking up attribution. Clients see specific, defensible attribution language.

---

## E. AI Timeline Generation (Standalone — Case Reports Page)

**Trigger:** User generates a timeline report from the case reports page

**Path:** `/api/reports/generate-timeline/<case_uuid>` → `AITimelineGenerator` → event grouping → per-segment AI narrative generation

**Current state:** The timeline generator groups events by type and time window, then asks the LLM to write narrative for each segment. Like the report generator, it has no OpenCTI connection.

**Integration:** Nearly identical to the report generator approach. Add the same `_get_threat_intel_context()` method (or extract it to a shared base class / mixin since both generators inherit similar patterns). Inject it into the narrative prompt for each timeline segment so the LLM can contextualize event groups:

```
"This cluster of events (4624 → 5140 → 7045) matches the T1021.002 (SMB/Windows Admin Shares)
lateral movement pattern. This technique has been attributed to APT29, FIN7, and Wizard Spider
in recent campaigns."
```

The timeline generator already knows MITRE technique IDs for its event groups (from Hayabusa rule mappings). The OpenCTI lookup per technique is a single cached call.

**Effort:** Small (if report generator is done first — reuse the same method). Medium if done standalone.

**Impact:** Timeline narratives move from "at 14:32 UTC, admin share access was observed" to "at 14:32 UTC, admin share access was observed, consistent with T1021.002 lateral movement attributed to [group]."

---

## F. Chat Agent (Standalone — Streaming Chat)

**Trigger:** User opens the chat interface (available in multiple contexts)

**Path:** `utils/chat_agent.py` → `build_system_prompt()` → tool execution via `chat_tools.py`

**Current state:** Four tools available: `query_events`, `count_events`, `get_findings`, `lookup_ioc`. The system prompt includes case metadata, analysis summary, and AI synthesis. No OpenCTI.

**Integration — Two parts:**

**F1. New chat tool: `lookup_threat_intel`**

Add to `chat_tools.py`:

```python
TOOL_DEFINITIONS.append({
    "type": "function",
    "function": {
        "name": "lookup_threat_intel",
        "description": "Query OpenCTI threat intelligence. Look up a MITRE technique ID, IOC value, or threat actor name. Use for questions like 'what groups use T1003?' or 'is this IP in our threat intel?'.",
        "parameters": {
            "type": "object",
            "properties": {
                "query_type": {
                    "type": "string",
                    "enum": ["technique", "ioc", "actor"],
                    "description": "What to look up"
                },
                "value": {
                    "type": "string",
                    "description": "The technique ID (T1003), IOC value (IP/hash/domain), or actor name"
                }
            },
            "required": ["query_type", "value"]
        }
    }
})

@register_tool("lookup_threat_intel")
def lookup_threat_intel(case_id: int, query_type: str, value: str, **kwargs) -> Dict:
    from utils.opencti_context import OpenCTIContextProvider

    provider = OpenCTIContextProvider(case_id)
    if not provider.is_available():
        return {"error": "OpenCTI is not configured or unavailable"}

    if query_type == "technique":
        ctx = provider.get_attack_pattern_context(value)
        if not ctx.get('technique_name'):
            return {"found": False, "value": value}
        return {
            "found": True,
            "technique": ctx['technique_name'],
            "mitre_id": value,
            "detection_guidance": (ctx.get('detection_guidance') or '')[:300],
            "threat_actors": [a['name'] for a in ctx.get('threat_actors', [])[:5]],
            "platforms": ctx.get('platforms', []),
        }

    elif query_type == "ioc":
        result = provider.enrich_ioc(value, 'Unknown')
        return result

    elif query_type == "actor":
        actors = provider.get_threat_actor_context([])  # Full list
        matches = [a for a in actors if value.lower() in a.get('name', '').lower()]
        if not matches:
            return {"found": False, "value": value}
        actor = matches[0]
        return {
            "found": True,
            "name": actor['name'],
            "aliases": actor.get('aliases', []),
            "techniques": [t['mitre_id'] for t in actor.get('attack_patterns', [])[:10]],
        }

    return {"error": f"Unknown query_type: {query_type}"}
```

**F2. Threat intel summary in system prompt:**

In `build_system_prompt()`, if OpenCTI is available and analysis results exist, add a brief threat intel line:

```python
# After the synthesis_block
threat_intel_block = ""
if case_context.get('opencti_summary'):
    ti = case_context['opencti_summary']
    threat_intel_block = f"\n\nThreat Intelligence: {ti}"
```

This requires `get_case_context()` in `chat_agent.py` to optionally pull a one-line OpenCTI summary (top matching threat actors). Keep it brief — the system prompt is already large and this runs on every message.

**Effort:** Medium. New tool definition, implementation, and registration. System prompt change is small.

**Impact:** Analysts can interrogate threat intelligence conversationally: "which threat groups use the techniques we detected?" → tool call → grounded answer.

---

## G. SIGMA Gap Detection (Bonus — Standalone or via Case Analyzer)

**Current state:** `OpenCTIContextProvider.get_sigma_rules_not_in_hayabusa()` already identifies SIGMA rules in OpenCTI that aren't covered by the local Hayabusa ruleset. The RAG sync task (`rag_sync_opencti_patterns`) imports them into the `AttackPattern` table. But they sit there as stored YAML — they're never executed against case events.

**Integration:** `utils/sigma_converter.py` exists and can convert SIGMA rules to ClickHouse queries. Wire these together:

1. During case analysis (or as a standalone hunting action), query `AttackPattern` for `source='opencti_sigma'` rules not in Hayabusa
2. Convert each rule to a ClickHouse query via `sigma_converter`
3. Execute against case events
4. Surface matches as additional findings

This could be a new Phase 4.5 in the case analyzer (between Hayabusa correlation and pattern analysis) or a standalone button in the Hunting tab ("Run OpenCTI SIGMA Rules").

**Effort:** High. SIGMA-to-ClickHouse conversion is non-trivial and rule-dependent. Many SIGMA rules won't map cleanly to the CaseScope event schema.

**Impact:** Fills detection coverage gaps automatically. If OpenCTI has a SIGMA rule for a technique that Hayabusa doesn't cover, CaseScope can still detect it.

---

## Priority and Sequencing

| Priority | System | Effort | Impact | Depends On |
|----------|--------|--------|--------|------------|
| **1** | D. AI Report Generation | Medium-high | Highest — every report goes to a client | Nothing |
| **2** | A1. Synthesis Checkpoint | Small | High — data already exists, just needs plumbing | Nothing |
| **3** | B. AI Pattern Correlation | Medium | High — improves the primary hunting tool | Nothing |
| **4** | C. Ask AI | Medium | Medium-high — most-used interactive feature | Nothing |
| **5** | A2. Suggested Actions | Medium | Medium — makes recommendations specific | A1 (shares context) |
| **6** | E. AI Timeline Generation | Small | Medium — reuses report generator work | D (shared method) |
| **7** | F. Chat Agent | Medium | Lower — least-used AI interface currently | Nothing |
| **8** | G. SIGMA Gap Detection | High | Variable — depends on OpenCTI rule quality | Nothing |

Items 1-4 are independent and can be built in parallel. Item 5 shares context with A1. Item 6 directly reuses work from D. Items 7-8 are standalone but lower priority.

---

## Shared Infrastructure

All integrations use the same components:

- **`OpenCTIContextProvider`** — already built, with caching via `OpenCTICache`
- **Cache TTL** — 24 hours default. Standalone pipelines (B-F) will populate the cache on first call; subsequent calls (even across pipelines) hit cache. This means if the user runs AI Pattern Correlation first, the report generator benefits from cached results.
- **Graceful degradation** — every integration must check `provider.is_available()` and proceed without OpenCTI if unavailable. No pipeline should fail because OpenCTI is down.
- **Mode awareness** — the case analyzer already has Mode C/D gating. Standalone pipelines should check `SystemSettings.get(SettingKeys.OPENCTI_ENABLED)` independently since they don't go through the mode system.

---

## What This Replaces

This plan makes the LoRA training proposal unnecessary for its stated goals. The training concept aimed to make LLMs "know more about cybersecurity" by fine-tuning on CyberLLMInstruct. But the three profile types it targeted — report writing, pattern detection, and timeline generation — are exactly the three systems (D, B, E) where injecting OpenCTI context at prompt time achieves the same outcome without training. The LLM doesn't need to have learned about APT29's TTPs during training if it receives that information in every prompt alongside the case data.

The key difference: LoRA training would produce a static model that knows what CyberLLMInstruct contained at training time. OpenCTI integration produces dynamic context that reflects the user's current threat intelligence, updated continuously.
