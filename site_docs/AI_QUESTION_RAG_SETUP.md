# CaseScope AI Question (RAG) Setup Guide

## Overview

The AI Question feature uses **Retrieval-Augmented Generation (RAG)** to let analysts ask natural language questions about case events. Instead of writing complex OpenSearch queries, analysts can ask questions like:

- "Were there any signs of lateral movement?"
- "What happened in the 30 minutes before the ransomware executed?"
- "Show me failed login attempts from external IPs"

The system finds relevant events using semantic search, passes them to the AI, and generates an analysis grounded in actual evidence.

---

## Architecture (Optimized for 8GB GPU)

```
┌─────────────────────────────────────────────────────────────────┐
│                    AI QUESTION WORKFLOW                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────────┐     ┌──────────────────┐                 │
│  │ 1. KEYWORD SEARCH │────▶│ OpenSearch       │  Fast lookup    │
│  └──────────────────┘     └──────────────────┘                 │
│           │                        │                            │
│           │                        ▼                            │
│           │               100 candidate events                  │
│           │                        │                            │
│           ▼                        ▼                            │
│  ┌──────────────────┐     ┌──────────────────┐                 │
│  │ 2. EMBED QUESTION │────▶│ sentence-        │  CPU (~5ms)     │
│  └──────────────────┘     │ transformers     │                 │
│                           └──────────────────┘                 │
│           │                        │                            │
│           │                        ▼                            │
│  ┌──────────────────┐     ┌──────────────────┐                 │
│  │ 3. EMBED EVENTS   │────▶│ Batch embed 100  │  CPU (~500ms)   │
│  └──────────────────┘     │ events           │                 │
│                           └──────────────────┘                 │
│           │                        │                            │
│           │                        ▼                            │
│  ┌──────────────────┐     ┌──────────────────┐                 │
│  │ 4. SEMANTIC RANK  │────▶│ Cosine similarity│  Re-rank by     │
│  └──────────────────┘     │ + OpenSearch     │  meaning        │
│                           └──────────────────┘                 │
│           │                        │                            │
│           │                        ▼                            │
│           │               Top 20 events                         │
│           │                        │                            │
│           ▼                        ▼                            │
│  ┌──────────────────┐     ┌──────────────────┐                 │
│  │ 5. LLM ANALYSIS   │────▶│ dfir-llama       │  GPU (8GB)      │
│  └──────────────────┘     │ via Ollama       │                 │
│                           └──────────────────┘                 │
│                                    │                            │
│                                    ▼                            │
│                           Grounded answer with                  │
│                           evidence citations                    │
└─────────────────────────────────────────────────────────────────┘
```

### Model Assignment

| Component | Model | Size | Runs On | Why |
|-----------|-------|------|---------|-----|
| **Embedding** | `all-MiniLM-L6-v2` | 90MB | CPU | Blazing fast, leaves GPU free |
| **LLM** | dfir-llama/mistral | 4-5GB | GPU | Needs compute power |

**Key Point**: Embeddings run on CPU at ~1000/second. This keeps your 8GB GPU 100% available for LLM inference.

### Zero Ingestion Impact

```
INGESTION PIPELINE (unchanged):       AI QUESTION (separate):
┌──────────────────────────┐          ┌──────────────────────────┐
│ Upload → Parse → Index   │          │ On-demand only           │
│ → Chainsaw → IOC Hunt    │          │ Triggered by analyst     │
│                          │          │ clicking "AI Question"   │
│ NO EMBEDDINGS            │          │                          │
│ NO GPU USAGE             │          │ Embeddings: CPU          │
│ 8 workers process files  │          │ LLM: GPU                 │
└──────────────────────────┘          └──────────────────────────┘
```

---

## Installation

### Step 1: Install Python Dependencies

```bash
cd /opt/casescope/app
source ../venv/bin/activate

# Install sentence-transformers and numpy
pip install sentence-transformers numpy --break-system-packages

# Or use requirements.txt
pip install -r requirements.txt --break-system-packages
```

**First run note**: The embedding model (~90MB) downloads automatically on first use. This takes ~30 seconds once, then it's cached.

### Step 2: Verify DFIR Models Are Installed (for LLM)

The AI Question feature uses your existing DFIR models on GPU:

```bash
ollama list

# You should see one or more of:
# dfir-llama:latest
# dfir-mistral:latest  
# dfir-qwen:latest
# dfir-deepseek:latest
```

If none are installed:

```bash
# Pull base model
ollama pull llama3.1:8b-instruct-q4_K_M

# Create DFIR profile
cat > /tmp/dfir-llama.modelfile << 'EOF'
FROM llama3.1:8b-instruct-q4_K_M

SYSTEM """You are a Digital Forensics and Incident Response (DFIR) analyst. You analyze security events with precision and always ground your conclusions in evidence. You never fabricate or assume information not present in the data provided."""

PARAMETER temperature 0.3
PARAMETER num_ctx 16384
EOF

ollama create dfir-llama -f /tmp/dfir-llama.modelfile
```

### Step 3: Restart CaseScope

```bash
sudo systemctl restart casescope
sudo systemctl restart casescope-worker
```

### Step 4: Verify Installation

1. Go to any case's **Search Events** page
2. Click the **🤖 AI Question** button (purple gradient)
3. Ask a test question: "What events are in this case?"
4. Watch the response stream in

---

## How It Works

### Semantic Search vs Keyword Search

**Traditional keyword search** (what you have now):
- Query: "lateral movement"
- Finds: Events containing the exact words "lateral" or "movement"
- Misses: PsExec execution, WMI remote commands, RDP connections

**Semantic search** (what RAG adds):
- Query: "lateral movement"  
- Understands: This means "attacker moving between systems"
- Finds: PsExec, WMI, RDP, scheduled tasks on remote hosts, even without those exact words

### The Hybrid Approach

We combine both for best results:

1. **Keyword search** gets candidates quickly from OpenSearch
2. **Semantic re-ranking** sorts them by actual meaning relevance
3. **SIGMA/IOC boost** prioritizes flagged events
4. **LLM analysis** synthesizes findings into coherent answer

---

## Usage Examples

### Good Questions

| Question | What It Finds |
|----------|---------------|
| "Were there any signs of lateral movement?" | PsExec, WMI, RDP, SMB connections between internal hosts |
| "What happened before the ransomware executed?" | Timeline of events leading up to encryption |
| "Show me credential theft attempts" | LSASS access, SAM dumps, Mimikatz indicators |
| "Any persistence mechanisms?" | Scheduled tasks, services, registry run keys |
| "Failed authentication from external IPs" | 4625 events with non-RFC1918 source addresses |

### Understanding Responses

The AI will:
1. Reference specific events: "Event 3 shows..."
2. Quote actual values from events
3. Identify attack patterns
4. Admit when evidence is insufficient

Example:
```
Based on the retrieved events, there is evidence of credential harvesting:

Event 5 shows explicit credential use (Event ID 4648) by svc_backup 
targeting DC01 at 14:32:05. This service account typically only accesses 
file servers.

Event 8 shows LSASS memory access at 14:32:47, consistent with tools 
like Mimikatz.

Event 12 shows a scheduled task created at 14:35:12 using the harvested 
credentials, establishing persistence.
```

### Viewing and Interacting with Evidence Events

After the AI generates a response, you can load the exact events it analyzed into the main search results table for full interaction:

1. **In the Modal**: 
   - View a preview of the first 5 evidence events with flags and timestamps
   - See total count: "📋 Evidence Events (20)"
   - Click the **"Show in Search Results →"** button (purple gradient)

2. **Result**: 
   - Modal closes automatically
   - Search results table loads with ONLY the AI evidence events
   - Header updates to show "X AI evidence events"
   - Table scrolls into view

3. **Full Interaction Available**:
   - **⭐ Tag Events**: Click star icon to mark important events for your timeline/report
   - **👁️ View Details**: Click eye icon to open full event modal with raw EventData
   - **Export**: Use bulk operations to export the evidence set
   - **Pivot**: From tagged events, continue investigating related activity
   - **All Standard Features**: Filtering, sorting, column management work normally

4. **Use Case Example**:
   ```
   Analyst asks: "What lateral movement occurred?"
   → AI responds with analysis referencing 20 events
   → Modal shows preview: "5 events shown, ...and 15 more"
   → Click "Show in Search Results" button
   → Modal closes, 20 events load in table below
   → Analyst tags 5 key events showing PsExec/WMI activity
   → Analyst views full details of Event 8 (LSASS access)
   → Analyst exports tagged events for incident report
   ```

This workflow provides:
- **Evidence Verification**: Compare AI conclusions against raw event data
- **Investigation Continuity**: Seamlessly transition from AI analysis to manual triage
- **Report Building**: Tag and export the exact events AI used in its analysis
- **Audit Trail**: All analyst interactions logged for compliance

---

## Performance Tuning

### For Your 8GB GPU Setup

| Setting | Recommendation | Why |
|---------|----------------|-----|
| Max Events | 20-30 | More events = longer LLM processing |
| LLM Model | dfir-llama or dfir-mistral | Fits fully in 8GB VRAM |
| Embedding | CPU (automatic) | Keeps GPU free for LLM |

### Typical Response Times

| Phase | Time | Notes |
|-------|------|-------|
| Keyword search | 50-200ms | OpenSearch query |
| Question embedding | ~5ms | Single embedding |
| Event embedding (50) | ~300-500ms | Batched on CPU |
| Re-ranking | ~10ms | Numpy operations |
| LLM generation | 10-30s | Depends on response length |

**Total**: 15-35 seconds for a complete answer

---

## Troubleshooting

### "AI Question" Button Grayed Out

```bash
# Check Ollama
systemctl status ollama
curl http://localhost:11434/api/tags

# Check for LLM models
ollama list
```

### "sentence-transformers not installed"

```bash
cd /opt/casescope/app
source ../venv/bin/activate
pip install sentence-transformers --break-system-packages
sudo systemctl restart casescope
```

### Slow First Query

The embedding model downloads on first use (~90MB). Subsequent queries are fast.

### LLM Timeout

If your GPU is busy with other tasks:
- Reduce "Max Events" to 10
- Use dfir-mistral (faster than dfir-llama)
- Check `nvidia-smi` for GPU memory usage

### Poor Quality Results

- Try more specific questions
- Use DFIR terminology: "4624", "lateral movement", "persistence"
- Check that events exist in the case (run a regular search first)

---

## Files Reference

| File | Purpose |
|------|---------|
| `app/ai_search.py` | RAG backend - embeddings, semantic search, LLM integration |
| `app/routes/ai_search.py` | Flask API routes for AI Question (includes `/status`, `/ask`, `/events` endpoints) |
| `app/templates/search_events.html` | UI with AI Question button, modal, and evidence events display |
| `app/requirements.txt` | Updated with sentence-transformers, numpy |

### Key Functions in search_events.html

| Function | Purpose |
|----------|---------|
| `showAIQuestionModal()` | Opens the AI Question modal |
| `submitAIQuestion()` | Sends question to backend, streams response via SSE |
| `handleAIStreamData(data)` | Processes streaming data: status, events preview, response chunks |
| `showAIEventsInSearchResults()` | Populates main search results table with AI evidence events for full interaction (tagging, viewing, exporting) |

### API Endpoints (app/routes/ai_search.py)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/case/<id>/ai-search/status` | GET | Check if Ollama and LLM are available |
| `/case/<id>/ai-search/ask` | POST | Submit question, returns SSE stream with AI response and full event data |

**Note**: As of v1.27.6+, the `/events` endpoint is no longer used. Event data is now streamed directly in the `/ask` response for better performance.

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.27.0 | Nov 2025 | Initial RAG feature with semantic search and streaming responses |
| 1.27.1 | Nov 2025 | Bugfixes: modal styling, log_action parameters |
| 1.27.2 | Nov 2025 | Enhanced keyword extraction (CamelCase, usernames, quoted strings) |
| 1.27.3 | Nov 2025 | Robust search (multi-match, fuzziness, fallback) |
| 1.27.4 | Nov 2025 | "View in Search Results" button to display evidence events in table |
| 1.27.5 | Nov 2025 | Performance fixes for large indices (field limiting, timeouts, keyword capping) |
| 1.27.6 | Nov 2025 | Simplified event display: show events directly in modal (removed external fetch) |
| 1.27.7 | Nov 2025 | Prioritize tagged events: boost analyst-tagged events highest in results |
| 1.27.8 | Nov 2025 | Bugfix: datetime JSON serialization error in event streaming |
| 1.27.9 | Nov 2025 | **Enhancement**: Evidence events now load into main search results table for full analyst interaction (tagging, viewing details, exporting) |
