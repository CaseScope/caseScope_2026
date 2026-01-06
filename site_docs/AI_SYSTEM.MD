# CaseScope - AI System Documentation

Last Updated: 2026-01-06

## Table of Contents
- [Overview](#overview)
- [Architecture](#architecture)
- [Setup & Installation](#setup--installation)
- [AI Features](#ai-features)
- [How It Works](#how-it-works)
- [API Endpoints](#api-endpoints)
- [Frontend Integration](#frontend-integration)
- [Configuration](#configuration)
- [Security & Permissions](#security--permissions)
- [Performance](#performance)
- [Troubleshooting](#troubleshooting)

---

## Overview

CaseScope's AI system provides intelligent threat analysis, natural language querying, and automated threat hunting capabilities powered by **local LLMs** (Large Language Models). The system is **fully self-hosted** with no external API dependencies, ensuring data privacy and security.

### Key Capabilities

1. **Natural Language Queries** - Convert questions to OpenSearch DSL
2. **Event Analysis** - AI-powered event interpretation with MITRE ATT&CK context
3. **Threat Hunting** - Automatic hunt query generation from known bad events
4. **RAG Chat Assistant** - Conversational AI with threat intelligence context
5. **IOC Extraction** - Automated extraction of indicators from text/events

### Core Components

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **LLM Runtime** | Ollama | Local model inference (CPU/GPU) |
| **Chat Model** | Qwen2.5 7B (Q4_K_M) | Event analysis, chat, IOC extraction |
| **Code Model** | Qwen2.5-Coder 7B (Q4_K_M) | OpenSearch DSL generation |
| **Embedding Model** | FastEmbed (bge-small-en-v1.5) | Text embeddings for RAG |
| **Vector Database** | PostgreSQL + pgvector | Semantic search over 3,700+ patterns |
| **Knowledge Base** | Sigma + MITRE ATT&CK | Detection rules & attack techniques |

### Design Principles

✅ **Privacy-First**: All processing happens locally, no external APIs  
✅ **Toggleable**: Can be fully disabled via `AI_ENABLED = False`  
✅ **Graceful Degradation**: System works without AI if unavailable  
✅ **Auditable**: All AI actions logged to `audit_log` table  
✅ **Contextual**: RAG provides grounded responses with sources  

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      CaseScope AI System                         │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────┐      ┌─────────────────┐      ┌──────────────┐
│   Web Browser   │◄────►│  Flask Backend  │◄────►│  PostgreSQL  │
│  (JavaScript)   │      │   (Python)      │      │  + pgvector  │
└─────────────────┘      └────────┬────────┘      └──────────────┘
                                  │                        ▲
                                  │                        │
                         ┌────────▼────────┐              │
                         │  AI Routes      │              │
                         │  (ai.py)        │              │
                         │  - /api/ai/*    │              │
                         └────────┬────────┘              │
                                  │                        │
        ┌─────────────────────────┼────────────────────┐  │
        │                         │                    │  │
┌───────▼────────┐    ┌───────────▼───────┐    ┌──────▼──────┐
│  LLM Client    │    │  Vector Store     │    │   Audit     │
│  (llm_client)  │    │  (vector_store)   │◄───┤   Logger    │
│                │    │                   │    │             │
│ • Query Gen    │    │ • Sigma Rules     │    └─────────────┘
│ • Analysis     │    │ • MITRE ATT&CK    │
│ • Hunt Gen     │    │ • Embeddings      │
│ • IOC Extract  │    │ • Similarity      │
│ • Chat         │    │   Search          │
└────────┬───────┘    └───────────────────┘
         │
         │ HTTP
         ▼
┌─────────────────┐
│     Ollama      │
│  (Local Server) │
│                 │
│ • Qwen2.5 7B    │ ◄── Chat & Analysis
│ • Qwen2.5-Coder │ ◄── DSL Generation
│                 │
│ Port: 11434     │
└─────────────────┘

Data Flow Example (Natural Language Query):
1. User: "Show me failed logins from external IPs"
2. Frontend: POST /api/ai/query
3. AI Route: Validate, auth check
4. Vector Store: Search for relevant patterns (Sigma + MITRE)
5. LLM Client: Generate OpenSearch DSL with pattern context
6. OpenSearch: Execute query, return events
7. Audit Logger: Log action
8. Frontend: Display results + DSL + patterns used
```

---

## Setup & Installation

### Prerequisites

1. **Operating System**: Linux (Ubuntu 20.04+ recommended)
2. **RAM**: 16GB minimum (8GB for LLM, 4GB for OS/services, 4GB buffer)
3. **Storage**: 10GB for models + 5GB for data
4. **Python**: 3.8+
5. **PostgreSQL**: 14+ with pgvector extension

### Installation Steps

#### 1. Install Ollama

```bash
# Download and install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Start Ollama service
sudo systemctl enable ollama
sudo systemctl start ollama

# Verify running
sudo systemctl status ollama
```

#### 2. Download LLM Models

```bash
# Chat model (event analysis, IOC extraction, chat)
ollama pull qwen2.5:7b-instruct-q4_k_m

# Code model (DSL generation)
ollama pull qwen2.5-coder:7b-instruct-q4_k_m

# Verify models
ollama list
# Should show:
# qwen2.5:7b-instruct-q4_k_m     4.7 GB
# qwen2.5-coder:7b-instruct-q4_k_m   4.9 GB
```

**Model Details**:
- **Quantization**: Q4_K_M (4-bit, medium quality)
- **Size**: ~5GB each
- **Context**: 32K tokens
- **Speed**: 10-20 tokens/sec (CPU), 30-80 tokens/sec (GPU)

#### 3. Install PostgreSQL pgvector Extension

```bash
# Install pgvector
sudo apt update
sudo apt install postgresql-14-pgvector

# Enable in CaseScope database
sudo -u postgres psql casescope -c "CREATE EXTENSION IF NOT EXISTS vector;"

# Run migration
sudo -u postgres psql casescope -f /opt/casescope/migrations/add_pgvector_patterns.sql
```

#### 4. Download Threat Intelligence Data

```bash
cd /opt/casescope/data

# Clone Sigma rules
git clone https://github.com/SigmaHQ/sigma.git
# Rules location: /opt/casescope/data/sigma/rules/

# Download MITRE ATT&CK (STIX 2.0 JSON)
cd /opt/casescope/data/sigma
wget https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json -O mitre_attack.json
```

#### 5. Ingest Patterns into Vector Store

```bash
cd /opt/casescope
source venv/bin/activate

# Run ingestion script
python3 scripts/ingest_patterns.py

# Expected output:
# ✓ Ingested 3,142 Sigma rules
# ✓ Ingested 623 MITRE techniques
# Total patterns in store: 3,765
```

**This step is critical!** Without patterns, RAG will not work.

#### 6. Enable AI in Configuration

Edit `/opt/casescope/app/config.py`:

```python
# Enable AI features
AI_ENABLED = True

# Auto-detect availability (recommended)
AI_AUTO_DETECT = True

# Ollama connection
OLLAMA_HOST = 'http://localhost:11434'

# Model names (must match ollama list)
LLM_MODEL_CHAT = 'qwen2.5:7b-instruct-q4_k_m'
LLM_MODEL_CODE = 'qwen2.5-coder:7b-instruct-q4_k_m'

# Embedding model (FastEmbed, downloaded automatically)
EMBEDDING_MODEL = 'BAAI/bge-small-en-v1.5'

# Data paths
SIGMA_RULES_PATH = '/opt/casescope/data/sigma/rules'
MITRE_ATTACK_PATH = '/opt/casescope/data/sigma/mitre_attack.json'

# RAG tuning
AI_MAX_CONTEXT_EVENTS = 50  # Max events to send to LLM
AI_RAG_TOP_K = 5            # Number of patterns to retrieve
```

#### 7. Restart Flask Service

```bash
sudo systemctl restart casescope-new
sudo systemctl status casescope-new
```

#### 8. Verify AI Status

Navigate to **Settings → AI Configuration** in CaseScope UI. Status should show:
- ✅ Ollama: Connected
- ✅ Vector Store: 3,765 patterns
- ✅ Models: Ready

Or via API:
```bash
curl -H "Cookie: session=..." http://localhost:5001/api/ai/status
```

---

## AI Features

### 1. Natural Language Queries

**What It Does**: Converts natural language questions into OpenSearch DSL queries.

**Example**:
- **Input**: "Show me failed login attempts from external IPs in the last 24 hours"
- **Output**: OpenSearch DSL query + executed results

**How It Works**:
1. User enters question in AI Assistant modal (Query tab)
2. System retrieves relevant Sigma rules (e.g., brute force detection)
3. LLM generates OpenSearch DSL with proper field names
4. Query executes against OpenSearch
5. Events returned with query DSL and patterns used

**Use Cases**:
- Quick ad-hoc searches without learning DSL syntax
- Complex multi-field queries (time + host + event ID)
- Exploratory analysis ("Show me unusual PowerShell activity")

**API Endpoint**: `POST /api/ai/query`

---

### 2. Event Analysis

**What It Does**: Analyzes selected events and explains what happened, with MITRE ATT&CK context.

**Example**:
- **Input**: 50 events showing `mimikatz.exe` execution
- **Output**: "This is **T1003 Credential Dumping** via Mimikatz. Events show LSASS process access (Event 10) followed by suspicious network connections (Event 3). High confidence malicious activity."

**How It Works**:
1. User selects events (search results, case events)
2. System summarizes events (hosts, event IDs, timeframe)
3. RAG retrieves relevant MITRE techniques & Sigma rules
4. LLM analyzes events with pattern context
5. Returns structured analysis with technique IDs

**Use Cases**:
- Understanding complex attack chains
- Incident response triage
- Report writing (LLM explains technical events in plain language)

**API Endpoint**: `POST /api/ai/analyze`

---

### 3. Threat Hunting Query Generation

**What It Does**: Given a known malicious event, generates hunt queries to find related activity.

**Example**:
- **Input**: Event showing `mimikatz.exe` execution on `WORKSTATION-01`
- **Output**: 5 hunt queries:
  1. Same host ±15 minutes (what happened before/after?)
  2. Same user on other hosts (lateral movement?)
  3. LSASS access across all hosts (fleet-wide credential dumping?)
  4. Kerberos ticket requests (golden ticket usage?)
  5. SMB/RDP connections from this host (where did attacker pivot?)

**How It Works**:
1. User marks event as "bad" (right-click → "Hunt Around This")
2. System extracts event metadata (host, user, process, time)
3. RAG retrieves related attack patterns (T1003, T1021, T1078)
4. LLM generates 5 hunt queries (DSL + descriptions)
5. User clicks "Execute" to run queries

**Use Cases**:
- Proactive threat hunting
- Scope determination (how far did attacker get?)
- Finding persistence mechanisms

**API Endpoint**: `POST /api/ai/hunt`

---

### 4. RAG Chat Assistant

**What It Does**: Conversational AI that answers DFIR questions with threat intelligence context.

**Example Questions**:
- "How do I detect lateral movement?"
- "What is MITRE ATT&CK T1078?"
- "Explain Event ID 4624 Logon Type 3"
- "What are common persistence techniques?"

**How It Works**:
1. User asks question in Chat tab
2. RAG retrieves relevant patterns from vector store
3. LLM generates response with pattern context
4. Conversation history maintained (last 10 messages)

**Use Cases**:
- Junior analyst training
- Quick threat intel lookups
- Understanding attack techniques

**API Endpoint**: `POST /api/ai/chat`

---

### 5. IOC Extraction

**What It Does**: Automatically extracts indicators of compromise from text or events.

**Example**:
- **Input**: EDR report with narrative text
- **Output**: Structured IOCs:
  ```json
  {
    "ip_addresses": ["192.168.1.100", "10.0.0.5"],
    "domains": ["evil[.]com", "malicious-site[.]com"],
    "file_hashes": {
      "md5": ["d41d8cd98f00b204e9800998ecf8427e"],
      "sha256": ["e3b0c44298fc1c149afbf4c8996fb924..."]
    },
    "file_names": ["mimikatz.exe", "payload.dll"],
    "registry_keys": ["HKLM\\Software\\Malware\\Run"],
    "cve_ids": ["CVE-2024-1234"]
  }
  ```

**How It Works**:
1. User pastes text or selects events
2. LLM extracts all IOCs using regex + context understanding
3. IOCs auto-defanged (`example.com` → `example[.]com`)
4. Duplicates removed

**Use Cases**:
- Parsing EDR reports
- Extracting IOCs from OSINT
- Building IOC lists for blocking

**API Endpoint**: `POST /api/ai/ioc`

---

## How It Works

### Request Flow (Detailed)

**Example: Natural Language Query**

```
1. User Input (Browser)
   ┌──────────────────────────────────────┐
   │ "Show me failed logins from         │
   │  external IPs in last 24 hours"     │
   └──────────────┬───────────────────────┘
                  │ POST /api/ai/query
                  ▼
2. Flask Route (app/routes/ai.py)
   ┌──────────────────────────────────────┐
   │ @require_ai decorator                │
   │ • Check AI enabled & available       │
   │ • Validate user permissions          │
   └──────────────┬───────────────────────┘
                  │
                  ▼
3. Vector Store Search (app/ai/vector_store.py)
   ┌──────────────────────────────────────┐
   │ PatternStore.search(query, k=5)      │
   │ • Embed query (384-dim vector)       │
   │ • Cosine similarity search (pgvector)│
   │ • Return top-5 patterns              │
   │                                      │
   │ Results:                             │
   │ • sigma_failed_logon_brute_force     │
   │ • mitre_T1110 (Brute Force)         │
   │ • sigma_suspicious_logon_external   │
   └──────────────┬───────────────────────┘
                  │
                  ▼
4. LLM Query Generation (app/ai/llm_client.py)
   ┌──────────────────────────────────────┐
   │ LLMClient.generate_opensearch_dsl()  │
   │                                      │
   │ Prompt:                              │
   │ ┌──────────────────────────────────┐ │
   │ │ Convert question to DSL.         │ │
   │ │                                  │ │
   │ │ Relevant patterns:               │ │
   │ │ • Sigma: failed_logon_brute_force│ │
   │ │ • MITRE: T1110 Brute Force       │ │
   │ │                                  │ │
   │ │ Question: Show me failed logins..│ │
   │ │                                  │ │
   │ │ Return JSON DSL query.           │ │
   │ └──────────────────────────────────┘ │
   │                                      │
   │ Ollama (Qwen2.5-Coder 7B)           │
   │ • Inference: ~5-20 seconds          │
   │ • Output: JSON DSL                  │
   └──────────────┬───────────────────────┘
                  │
                  ▼
5. OpenSearch Execution
   ┌──────────────────────────────────────┐
   │ Generated DSL:                       │
   │ {                                    │
   │   "query": {                         │
   │     "bool": {                        │
   │       "must": [                      │
   │         {"term": {"event_id": 4625}},│
   │         {"range": {                  │
   │           "timestamp": {             │
   │             "gte": "now-24h"         │
   │           }                          │
   │         }}                           │
   │       ],                             │
   │       "must_not": [                  │
   │         {"terms": {"source_ip":      │
   │           ["192.168.0.0/16"]}}       │
   │       ]                              │
   │     }                                │
   │   },                                 │
   │   "size": 50                         │
   │ }                                    │
   │                                      │
   │ Execute → Return events              │
   └──────────────┬───────────────────────┘
                  │
                  ▼
6. Audit Log (audit_logger.py)
   ┌──────────────────────────────────────┐
   │ log_action('ai_query')               │
   │ • User: analyst1                     │
   │ • Action: AI Natural Language Query  │
   │ • Details: question, event count     │
   │ • Timestamp: 2025-12-24 10:30:00    │
   └──────────────┬───────────────────────┘
                  │
                  ▼
7. Response (JSON)
   ┌──────────────────────────────────────┐
   │ {                                    │
   │   "success": true,                   │
   │   "question": "Show me...",          │
   │   "dsl_query": {...},                │
   │   "patterns_used": [                 │
   │     {                                │
   │       "id": "sigma_failed_logon",    │
   │       "source": "sigma",             │
   │       "title": "Failed Logon Brute", │
   │       "score": 0.89                  │
   │     }                                │
   │   ],                                 │
   │   "events": [...],                   │
   │   "event_count": 42,                 │
   │   "execution_time_ms": 8234          │
   │ }                                    │
   └──────────────┬───────────────────────┘
                  │
                  ▼
8. Frontend Rendering (ai-assistant.js)
   ┌──────────────────────────────────────┐
   │ • Display events in table            │
   │ • Show DSL query (collapsible)       │
   │ • List patterns used with scores     │
   │ • Execution time badge               │
   └──────────────────────────────────────┘
```

### Key Design Decisions

**Why Qwen2.5 over GPT/Claude?**
- ✅ Fully local (no API calls, no data leakage)
- ✅ Free (no per-token costs)
- ✅ Fast enough on CPU (10-20 tokens/sec)
- ✅ Excellent performance for 7B model
- ✅ Commercial-friendly license

**Why Two Models?**
- **Qwen2.5-Coder**: Optimized for code/DSL generation (structured outputs)
- **Qwen2.5**: Better for analysis, chat, IOC extraction (natural language)

**Why RAG?**
- ✅ Prevents hallucination (LLM can't make up techniques)
- ✅ Always current (update Sigma rules without retraining)
- ✅ Traceable (every response shows which patterns were used)

**Why Top-K=5?**
- Balance: More patterns = better context, but slower inference
- Token budget: 5 patterns ≈ 1,000 tokens (leaves room for events)
- Quality: Beyond 5, relevance drops significantly

---

## API Endpoints

All endpoints require authentication (`@login_required`). Most require administrator role.

### GET /api/ai/status

**Check AI system status**

**Response**:
```json
{
  "enabled": true,
  "available": true,
  "status": "operational",
  "message": "AI features ready",
  "components": {
    "ollama": true,
    "vector_store": true,
    "models": true
  }
}
```

---

### POST /api/ai/query

**Convert natural language to OpenSearch DSL and execute**

**Permissions**: `@admin_required`

**Request**:
```json
{
  "question": "Show me failed login attempts from external IPs",
  "case_id": 123,    // Optional: filter to case
  "limit": 50        // Optional: max events (default: 50)
}
```

**Response**:
```json
{
  "success": true,
  "question": "Show me...",
  "dsl_query": {...},
  "patterns_used": [
    {
      "id": "sigma_failed_logon",
      "source": "sigma",
      "title": "Failed Logon Brute Force",
      "score": 0.89
    }
  ],
  "events": [...],
  "event_count": 42,
  "total_hits": 142,
  "execution_time_ms": 5234
}
```

---

### POST /api/ai/analyze

**Analyze events with RAG context**

**Permissions**: `@admin_required`

**Request**:
```json
{
  "events": [...],                    // Events to analyze
  "question": "What happened?",       // Optional: specific question
  "context": "Suspected breach"       // Optional: additional context
}
```

**Response**:
```json
{
  "success": true,
  "analysis": "These events indicate T1003 Credential Dumping...",
  "patterns_referenced": [
    {
      "id": "mitre_T1003",
      "source": "mitre",
      "title": "Credential Dumping",
      "score": 0.92
    }
  ],
  "event_count": 50
}
```

---

### POST /api/ai/hunt

**Generate hunt queries from known bad event**

**Permissions**: `@admin_required`

**Request**:
```json
{
  "event": {...},              // The known malicious event
  "hunt_scope": "all"          // "host", "user", "network", "all"
}
```

**Response**:
```json
{
  "success": true,
  "hunt_queries": [
    {
      "description": "Same host, ±15 minute time window",
      "dsl": {...},
      "rationale": "Find events before/after this activity"
    },
    {
      "description": "Same user on other hosts",
      "dsl": {...},
      "rationale": "Detect lateral movement"
    }
  ],
  "patterns_used": [...]
}
```

---

### POST /api/ai/chat

**Chat with RAG-powered assistant**

**Permissions**: `@admin_required`

**Request**:
```json
{
  "message": "How do I detect lateral movement?",
  "history": [                // Optional: conversation history
    {"role": "user", "content": "..."},
    {"role": "assistant", "content": "..."}
  ],
  "context_events": [...]     // Optional: events for context
}
```

**Response**:
```json
{
  "success": true,
  "response": "Lateral movement can be detected by monitoring...",
  "patterns_used": [
    {
      "id": "mitre_T1021",
      "source": "mitre",
      "title": "Remote Services",
      "score": 0.88
    }
  ]
}
```

---

### POST /api/ai/ioc

**Extract IOCs from text or events**

**Permissions**: `@login_required` (no admin required)

**Request**:
```json
{
  "text": "... report with IPs, domains, hashes ...",
  "events": [...]             // Alternative: extract from events
}
```

**Response**:
```json
{
  "success": true,
  "iocs": {
    "ip_addresses": ["192.168.1.100", "10.0.0.5"],
    "domains": ["evil[.]com"],
    "urls": ["https://malicious[.]site/payload.exe"],
    "file_hashes": {
      "md5": ["d41d8cd98f00b204e9800998ecf8427e"],
      "sha1": [],
      "sha256": ["e3b0c44298fc1c149afbf4c8996fb924..."]
    },
    "email_addresses": ["attacker@evil.com"],
    "file_names": ["mimikatz.exe", "payload.dll"],
    "registry_keys": ["HKLM\\Software\\Malware\\Run"],
    "cve_ids": ["CVE-2024-1234"]
  },
  "total_iocs": 12
}
```

---

## Frontend Integration

### AI Assistant Modal

**Location**: `templates/ai/assistant.html`  
**JavaScript**: `static/js/ai-assistant.js`  
**Trigger**: Click "Open AI Assistant" button on dashboard or settings page

**Modal Tabs**:

1. **Query** - Natural language to DSL
2. **Analyze** - Event analysis
3. **Hunt** - Hunt query generation  
4. **Chat** - Conversational assistant
5. **IOC Extract** - IOC extraction

**Opening Modal**:
```javascript
// From any page:
openAiModal();

// Open to specific tab:
openAiModal('hunt');  // Opens Hunt tab
```

**Modal Features**:
- ✅ Tab switching
- ✅ Loading states during API calls
- ✅ Error handling with user-friendly messages
- ✅ Copy to clipboard for DSL queries
- ✅ Event selection integration
- ✅ Conversation history (chat tab)

### Event Context Integration

**Right-click on events** (future enhancement):
```javascript
// Add "AI Actions" to context menu
contextMenu.addItem({
  label: "Analyze with AI",
  action: () => {
    openAiModal('analyze');
    loadEventsIntoModal(selectedEvents);
  }
});

contextMenu.addItem({
  label: "Hunt Around This Event",
  action: () => {
    openAiModal('hunt');
    loadEventIntoModal(selectedEvent);
  }
});
```

---

## Configuration

### config.py Settings

```python
# ============================================================================
# AI Configuration
# ============================================================================

# Master toggle - set to False to completely disable AI features
AI_ENABLED = True

# Auto-detect AI availability (recommended: True)
# If False, assumes AI is available if AI_ENABLED=True
AI_AUTO_DETECT = True

# Ollama connection
OLLAMA_HOST = 'http://localhost:11434'

# LLM Models (must match `ollama list` output)
LLM_MODEL_CHAT = 'qwen2.5:7b-instruct-q4_k_m'       # Chat, analysis, IOC extraction
LLM_MODEL_CODE = 'qwen2.5-coder:7b-instruct-q4_k_m' # DSL generation

# Embedding Model (FastEmbed, auto-downloaded)
EMBEDDING_MODEL = 'BAAI/bge-small-en-v1.5'  # 384-dimensional embeddings

# Data Sources
SIGMA_RULES_PATH = '/opt/casescope/data/sigma/rules'
MITRE_ATTACK_PATH = '/opt/casescope/data/sigma/mitre_attack.json'

# RAG Tuning
AI_MAX_CONTEXT_EVENTS = 50  # Max events to include in LLM context
AI_RAG_TOP_K = 5            # Number of patterns to retrieve from vector store

# Vector Store (PostgreSQL + pgvector)
VECTOR_STORE_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'database': 'casescope',
    'user': 'casescope',
    'password': 'casescope_password'
}
```

### Tuning Parameters

**AI_MAX_CONTEXT_EVENTS** (default: 50)
- **Higher** (100): Better analysis, but slower inference, risk of token overflow
- **Lower** (20): Faster, but may miss important context
- **Recommended**: 30-50

**AI_RAG_TOP_K** (default: 5)
- **Higher** (10): More context, better coverage, slower, more tokens
- **Lower** (3): Faster, less context, may miss relevant patterns
- **Recommended**: 3-7

**Token Budget** (per request):
- System prompt: ~200 tokens
- Patterns (k=5): ~1,000 tokens (200 each)
- Events (n=50): ~2,000 tokens (40 each)
- User question: ~50 tokens
- **Total input**: ~3,250 tokens
- **Response budget**: ~750 tokens
- **Total**: ~4,000 tokens (safe for 32K context window)

---

## Security & Permissions

### Access Control

**Administrator-Only Features**:
- Natural language queries (`/api/ai/query`)
- Event analysis (`/api/ai/analyze`)
- Hunt query generation (`/api/ai/hunt`)
- RAG chat (`/api/ai/chat`)

**All Users**:
- IOC extraction (`/api/ai/ioc`)
- Status check (`/api/ai/status`)

**Rationale**: Admin-only prevents untrained users from generating incorrect queries or misinterpreting AI analysis.

### Data Privacy

✅ **No External APIs**: All processing happens locally  
✅ **No Telemetry**: Ollama has no phone-home  
✅ **No Training**: Your data never trains the model  
✅ **Audit Trail**: All AI actions logged to `audit_log` table  

### Audit Logging

Every AI action logs:
- **User**: Who made the request
- **Action**: `ai_query`, `ai_analyze`, `ai_hunt`, `ai_chat`, `ai_ioc_extraction`
- **Details**: Question, event count, patterns used
- **Timestamp**: When it occurred
- **IP Address**: Client IP

**View Audit Logs**:
```sql
SELECT * FROM audit_log 
WHERE action LIKE 'ai_%' 
ORDER BY timestamp DESC 
LIMIT 100;
```

---

## Performance

### LLM Inference Speed

**Qwen2.5 7B (Q4_K_M quantization)**:

| Hardware | Prompt (tokens/sec) | Generation (tokens/sec) | 200 Token Response |
|----------|---------------------|-------------------------|-------------------|
| CPU 8-core | 2-5 | 10-20 | 10-20 seconds |
| GPU 8GB | 50-100 | 30-50 | 4-7 seconds |
| GPU 16GB+ | 100-200 | 50-80 | 2-4 seconds |

**Factors**:
- **CPU**: Cores (8+ recommended), AVX2 support
- **GPU**: VRAM (8GB minimum for Qwen 7B), CUDA/ROCm
- **RAM**: 16GB+ system RAM
- **Quantization**: Q4_K_M (4-bit) is 3-4x faster than FP16

### Vector Search Performance

**PostgreSQL + pgvector (HNSW index)**:

| Patterns | Search Time | Notes |
|----------|-------------|-------|
| 3,765 | 5-10ms | Current size |
| 10,000 | 10-20ms | 3x larger |
| 100,000 | 50-100ms | 25x larger |

**Query embedding**: ~100ms (FastEmbed, single text)

### End-to-End Latency

**Natural Language Query** (CPU):
- Vector search: 10ms
- Query embedding: 100ms
- LLM DSL generation: 10,000ms (10 sec)
- OpenSearch execution: 500ms
- **Total**: ~11 seconds

**With GPU (8GB)**:
- Vector search: 10ms
- Query embedding: 100ms
- LLM DSL generation: 5,000ms (5 sec)
- OpenSearch execution: 500ms
- **Total**: ~6 seconds

### Optimization Tips

**For CPU-Only Systems**:
1. Use smaller models (Qwen 1.5B instead of 7B)
2. Reduce `AI_RAG_TOP_K` from 5 to 3
3. Limit `AI_MAX_CONTEXT_EVENTS` to 20
4. Consider Groq/OpenRouter API (faster, but external)

**For GPU Systems**:
1. Ensure Ollama uses GPU: `ollama run qwen2.5:7b-instruct-q4_k_m`
2. Monitor: `nvidia-smi` or `rocm-smi`
3. Use larger quantization (Q5_K_M) for better quality

**For Vector Search**:
1. Rebuild HNSW index: `CREATE INDEX ... USING HNSW ... WITH (m = 16, ef_construction = 64)`
2. Tune ef_search: `SET hnsw.ef_search = 40;`

---

## Troubleshooting

### Issue: "AI features not available"

**Check 1: Is AI enabled?**
```bash
grep AI_ENABLED /opt/casescope/app/config.py
# Should show: AI_ENABLED = True
```

**Check 2: Is Ollama running?**
```bash
sudo systemctl status ollama
curl http://localhost:11434/api/tags
```

**Check 3: Are models downloaded?**
```bash
ollama list
# Should show qwen2.5:7b-instruct-q4_k_m and qwen2.5-coder:7b-instruct-q4_k_m
```

**Check 4: Is vector store populated?**
```bash
sudo -u postgres psql casescope -c "SELECT COUNT(*) FROM pattern_embeddings;"
# Should show 3,765+
```

**Fix**: Run `/opt/casescope/scripts/ingest_patterns.py`

---

### Issue: "LLM is very slow"

**Cause**: Running on CPU without GPU acceleration

**Check GPU usage**:
```bash
nvidia-smi  # For NVIDIA
rocm-smi    # For AMD
```

**Fix 1: Use GPU if available**
```bash
# Test GPU inference
ollama run qwen2.5:7b-instruct-q4_k_m
# Should show "Using GPU" in logs
```

**Fix 2: Use smaller model**
```bash
ollama pull qwen2.5:1.5b-instruct-q4_k_m
# Edit config.py: LLM_MODEL_CHAT = 'qwen2.5:1.5b-instruct-q4_k_m'
```

**Fix 3: Reduce context size**
```python
# In config.py:
AI_MAX_CONTEXT_EVENTS = 20  # Down from 50
AI_RAG_TOP_K = 3            # Down from 5
```

---

### Issue: "Generated DSL queries are incorrect"

**Cause**: LLM hallucinating field names or syntax

**Fix 1: Update patterns** (more examples → better learning)
```bash
cd /opt/casescope/data/sigma
git pull
cd /opt/casescope
python3 scripts/ingest_patterns.py
```

**Fix 2: Provide field schema** (already done in `generate_opensearch_dsl()`)

**Fix 3: Use larger/better model**
```bash
ollama pull qwen2.5:14b-instruct-q4_k_m  # 14B parameter model
# Edit config.py: LLM_MODEL_CODE = 'qwen2.5:14b-instruct-q4_k_m'
```

---

### Issue: "Chat responses are repetitive or low quality"

**Cause**: Model overfitting on prompt, low temperature, or exhausted context

**Fix 1: Clear conversation history** (modal auto-clears after 10 messages)

**Fix 2: Increase diversity** (edit `llm_client.py`):
```python
response = ollama.chat(
    model=self.chat_model,
    messages=messages,
    options={
        'temperature': 0.7,  # Default: 0.8 (higher = more creative)
        'top_p': 0.9,        # Nucleus sampling
        'repeat_penalty': 1.1 # Penalize repetition
    }
)
```

---

### Issue: "pgvector extension not found"

**Error**: `ERROR:  type "vector" does not exist`

**Fix**:
```bash
# Install pgvector
sudo apt update
sudo apt install postgresql-14-pgvector

# Enable extension
sudo -u postgres psql casescope -c "CREATE EXTENSION vector;"

# Verify
sudo -u postgres psql casescope -c "\dx"
# Should list "vector" extension
```

---

### Issue: "Out of memory errors"

**Cause**: Model too large for available RAM/VRAM

**Check memory usage**:
```bash
free -h            # System RAM
nvidia-smi         # GPU VRAM (if applicable)
ollama ps          # Ollama memory usage
```

**Fix 1: Use smaller quantization** (Q4 → Q3)
```bash
ollama pull qwen2.5:7b-instruct-q3_k_m  # 3-bit quantization (~3GB)
```

**Fix 2: Reduce concurrent users** (only 1 query at a time)

**Fix 3: Restart Ollama** (clear memory)
```bash
sudo systemctl restart ollama
```

---

## Summary

CaseScope's AI system provides powerful, **local, privacy-preserving** intelligence for DFIR investigations. Key highlights:

✅ **5 Core Features**: NL queries, event analysis, threat hunting, RAG chat, IOC extraction  
✅ **Fully Local**: No external APIs, all processing on-premises  
✅ **RAG-Powered**: 3,700+ Sigma rules & MITRE techniques for context  
✅ **Auditable**: All actions logged for compliance  
✅ **Toggleable**: Can be fully disabled if not needed  
✅ **Extensible**: Add more models, update patterns, tune parameters  

**Key Files**:
- `/opt/casescope/app/routes/ai.py` - API endpoints
- `/opt/casescope/app/ai/llm_client.py` - LLM interaction
- `/opt/casescope/app/ai/vector_store.py` - RAG implementation
- `/opt/casescope/app/ai/ai_toggle.py` - Feature toggling
- `/opt/casescope/scripts/ingest_patterns.py` - Pattern ingestion
- `/opt/casescope/templates/ai/assistant.html` - Frontend UI
- `/opt/casescope/static/js/ai-assistant.js` - Frontend logic

**Next Steps**:
1. Monitor LLM performance: `ollama ps` (check memory/CPU usage)
2. Update Sigma rules monthly: `cd /opt/casescope/data/sigma && git pull`
3. Re-ingest patterns after updates: `python3 scripts/ingest_patterns.py`
4. Tune `AI_RAG_TOP_K` and `AI_MAX_CONTEXT_EVENTS` based on feedback
5. Consider GPU upgrade if inference is too slow (3-10x speedup)

---

**For more details on RAG**: See `RAG_SYSTEM.MD` in this directory.

**Questions?** Check logs: `/opt/casescope/logs/celery_worker.log` or `/var/log/ollama.log`

