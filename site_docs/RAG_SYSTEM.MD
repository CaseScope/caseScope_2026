# CaseScope - RAG (Retrieval Augmented Generation) System

Last Updated: 2025-12-24

## Table of Contents
- [Overview](#overview)
- [Architecture](#architecture)
- [Setup & Configuration](#setup--configuration)
- [How RAG Works](#how-rag-works)
- [What RAG Does](#what-rag-does)
- [Technical Deep Dive](#technical-deep-dive)
- [Performance Considerations](#performance-considerations)
- [Troubleshooting](#troubleshooting)

---

## Overview

The RAG (Retrieval Augmented Generation) system enhances CaseScope's AI capabilities by providing the LLM with **relevant threat intelligence context** during analysis. Instead of relying solely on the LLM's training data, RAG dynamically retrieves relevant Sigma detection rules and MITRE ATT&CK techniques from a vector database, allowing the AI to provide **more accurate, up-to-date, and contextually relevant** responses.

### Key Benefits
- ✅ **Grounded in Real Threat Intelligence**: Responses backed by Sigma rules & MITRE ATT&CK
- ✅ **Always Up-to-Date**: Update detection rules without retraining the LLM
- ✅ **Reduced Hallucination**: LLM answers based on retrieved facts, not imagination
- ✅ **Traceable Sources**: Every response can reference specific rules/techniques
- ✅ **Domain-Specific**: Focused on DFIR/threat hunting, not general knowledge

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      CaseScope RAG Flow                      │
└─────────────────────────────────────────────────────────────┘

1. INGESTION (One-time Setup)
   ┌──────────────┐       ┌──────────────┐
   │ Sigma Rules  │       │ MITRE ATT&CK │
   │ (3,000 YAML) │       │ (600 JSON)   │
   └──────┬───────┘       └──────┬───────┘
          │                      │
          ├──────────────────────┤
          │  Parse & Extract     │
          │  Technique Metadata  │
          └──────────┬───────────┘
                     │
          ┌──────────▼──────────┐
          │  FastEmbed Model    │
          │  (bge-small-en-v1.5)│
          │  Generate 384-dim   │
          │  Embeddings         │
          └──────────┬──────────┘
                     │
          ┌──────────▼──────────┐
          │   PostgreSQL DB     │
          │   + pgvector ext    │
          │                     │
          │ pattern_embeddings  │
          │  - pattern_id       │
          │  - source (enum)    │
          │  - content (text)   │
          │  - embedding (vec)  │
          │  - metadata (jsonb) │
          └─────────────────────┘

2. RUNTIME (Per AI Request)
   ┌──────────────────┐
   │  User Question   │
   │ "Find lateral   │
   │  movement"       │
   └────────┬─────────┘
            │
   ┌────────▼─────────┐
   │ Embed Query      │
   │ (FastEmbed)      │
   └────────┬─────────┘
            │
   ┌────────▼─────────────────┐
   │ Vector Similarity Search │
   │ (Cosine Distance)        │
   │ Top-K = 5 patterns       │
   └────────┬─────────────────┘
            │
   ┌────────▼──────────────────┐
   │ Retrieved Patterns        │
   │ - T1021 RDP/SMB/WinRM    │
   │ - T1047 WMI              │
   │ - Sigma: lateral_movement │
   └────────┬──────────────────┘
            │
   ┌────────▼──────────────────┐
   │ Inject into LLM Prompt    │
   │ + User Question           │
   │ + Case Events (optional)  │
   └────────┬──────────────────┘
            │
   ┌────────▼──────────────────┐
   │ Ollama LLM Response       │
   │ (Qwen2.5 7B)             │
   │ Context-aware answer      │
   └───────────────────────────┘
```

---

## Setup & Configuration

### Prerequisites

1. **PostgreSQL 14+ with pgvector**:
   ```sql
   CREATE EXTENSION IF NOT EXISTS vector;
   ```

2. **Ollama Running Locally**:
   ```bash
   systemctl status ollama
   # Should be active (running)
   ```

3. **Models Downloaded**:
   ```bash
   ollama list
   # Should show:
   # - qwen2.5:7b-instruct-q4_k_m
   # - qwen2.5-coder:7b-instruct-q4_k_m
   ```

4. **Sigma Rules & MITRE ATT&CK**:
   ```bash
   ls /opt/casescope/data/sigma/
   # sigma/rules/    (Sigma detection rules)
   # mitre_attack.json (MITRE ATT&CK STIX 2.0)
   ```

### Configuration (`app/config.py`)

```python
# AI Feature Toggle
AI_ENABLED = True
AI_AUTO_DETECT = True  # Auto-disable if Ollama unavailable

# Ollama Connection
OLLAMA_HOST = 'http://localhost:11434'

# LLM Models
LLM_MODEL_CHAT = 'qwen2.5:7b-instruct-q4_k_m'       # Chat & analysis
LLM_MODEL_CODE = 'qwen2.5-coder:7b-instruct-q4_k_m' # DSL generation

# Embedding Model (FastEmbed, runs locally)
EMBEDDING_MODEL = 'BAAI/bge-small-en-v1.5'  # 384-dimensional embeddings

# Data Sources
SIGMA_RULES_PATH = '/opt/casescope/data/sigma/sigma/rules'
MITRE_ATTACK_PATH = '/opt/casescope/data/sigma/mitre_attack.json'

# RAG Tuning
AI_MAX_CONTEXT_EVENTS = 50  # Max events to send to LLM (token limits)
AI_RAG_TOP_K = 5            # Number of patterns to retrieve per query

# PostgreSQL Connection
VECTOR_STORE_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'database': 'casescope',
    'user': 'casescope',
    'password': 'casescope_password'
}
```

### Ingestion Process

**Step 1: Run the ingestion script**:
```bash
cd /opt/casescope
source venv/bin/activate
python3 scripts/ingest_patterns.py
```

**Output Example**:
```
=== Pattern Ingestion (PostgreSQL + pgvector) ===
Current patterns in store: 0
Ingesting Sigma rules from: /opt/casescope/data/sigma/sigma/rules
✓ Ingested 3,142 Sigma rules

Ingesting MITRE ATT&CK from: /opt/casescope/data/sigma/mitre_attack.json
✓ Ingested 623 MITRE techniques

=== Complete ===
Total patterns in store: 3,765
  - sigma: 3,142
  - mitre: 623
```

**What Happens**:
1. Script reads all `.yml` files from Sigma rules directory
2. Parses each rule (title, description, tags, detection logic)
3. Reads MITRE ATT&CK JSON (STIX 2.0 format)
4. Extracts techniques with IDs, names, tactics, descriptions
5. Generates 384-dimensional embeddings using FastEmbed
6. Inserts into PostgreSQL `pattern_embeddings` table
7. Creates HNSW index for fast similarity search

**Re-running**:
- Safe to re-run (uses `ON CONFLICT DO NOTHING`)
- Only new patterns are inserted
- Updates require manual deletion or `updated_at` tracking

---

## How RAG Works

### 1. Embedding Generation

**Text Embedding** converts text into a numerical vector that captures semantic meaning. Similar concepts have similar vectors.

**Model**: `BAAI/bge-small-en-v1.5`
- **Dimensions**: 384 (smaller = faster, larger = more accurate)
- **Type**: Sentence transformer (optimized for semantic search)
- **Speed**: ~1,000 texts/sec on CPU
- **Quality**: State-of-the-art on MTEB benchmark

**Example**:
```python
from fastembed import TextEmbedding

embedder = TextEmbedding(model_name="BAAI/bge-small-en-v1.5")

texts = [
    "Lateral movement via RDP",
    "Remote Desktop Protocol connection",
    "Malware execution"
]

embeddings = list(embedder.embed(texts))
# embeddings[0] shape: (384,)
# embeddings[0]: [0.023, -0.145, 0.891, ...]

# Similar concepts have high cosine similarity:
similarity(embeddings[0], embeddings[1]) = 0.87  # High (same concept)
similarity(embeddings[0], embeddings[2]) = 0.34  # Low (different concept)
```

### 2. Vector Storage (pgvector)

**pgvector** is a PostgreSQL extension for vector similarity search.

**Data Model**:
```sql
CREATE TABLE pattern_embeddings (
    id SERIAL PRIMARY KEY,
    pattern_id VARCHAR(200) UNIQUE,          -- "sigma_lateral_rdp", "mitre_T1021"
    source VARCHAR(50),                      -- "sigma" or "mitre"
    content TEXT,                            -- Full rule/technique text
    embedding VECTOR(384),                   -- 384-dim float array
    metadata JSONB,                          -- {title, level, tags, tactics}
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

-- HNSW index for fast approximate nearest neighbor search
CREATE INDEX ON pattern_embeddings 
USING HNSW (embedding vector_cosine_ops);
```

**HNSW Index** (Hierarchical Navigable Small World):
- **Algorithm**: Graph-based approximate nearest neighbor
- **Speed**: O(log N) vs O(N) for brute force
- **Quality**: 95%+ recall at 10x-100x speedup
- **Trade-off**: Uses more memory for index

### 3. Similarity Search

**Query Process**:
```python
def search(self, query: str, k: int = 5):
    # 1. Embed the user's question
    query_embedding = self._embed([query])[0]  # [0.123, -0.456, ...]
    
    # 2. Find closest vectors using cosine distance
    sql = """
        SELECT pattern_id, content, metadata,
               1 - (embedding <=> %s::vector) as similarity
        FROM pattern_embeddings
        ORDER BY embedding <=> %s::vector
        LIMIT %s
    """
    results = execute(sql, [query_embedding, query_embedding, k])
    
    # 3. Return top-K most similar patterns
    return results
```

**Distance Metric**: Cosine Distance (`<=>`)
- **Range**: 0 (identical) to 2 (opposite)
- **Similarity**: `1 - distance` = range 0-1
- **Why Cosine?**: Angle-based, not magnitude (better for text)

**Example Query**:
```python
query = "Find evidence of lateral movement"

# Top-5 results:
# 1. mitre_T1021 (RDP, SMB, WinRM) - similarity: 0.89
# 2. sigma_lateral_movement_rdp     - similarity: 0.87
# 3. sigma_psexec_lateral           - similarity: 0.83
# 4. mitre_T1047 (WMI)              - similarity: 0.79
# 5. sigma_admin_share_access       - similarity: 0.76
```

### 4. Context Injection

**Pattern**: Retrieved patterns are injected into the LLM prompt as context.

**Example Prompt**:
```
You are a DFIR analyst. Analyze these events and answer the question.

Relevant attack patterns:
---
MITRE ATT&CK Technique: T1021 - Remote Services
Tactics: Lateral Movement
Description: Adversaries may use valid accounts to log into a remote 
service (RDP, SMB, SSH, VNC) to move laterally.
---
Sigma Rule: Lateral Movement via RDP
Level: high
Tags: attack.lateral_movement, attack.t1021.001
Detection Logic: Detects RDP connections from internal IPs to multiple hosts
---

Events:
[{ "event_id": 4624, "logon_type": 10, "source_ip": "192.168.1.50" }]

Question: Is there evidence of lateral movement?

Provide a clear, concise analysis. Reference MITRE ATT&CK IDs.
```

**Benefits**:
- LLM has **specific** threat intelligence, not just generic knowledge
- Answers can reference **exact** technique IDs and rule names
- Reduces **hallucination** (making up techniques that don't exist)

---

## What RAG Does

### Use Case 1: Natural Language to OpenSearch DSL

**User Input**: "Show me failed logins from external IPs in the last hour"

**RAG Flow**:
1. Embed query → retrieve patterns mentioning "failed logons", "brute force"
2. Retrieved: `sigma_brute_force_rdp`, `mitre_T1110`
3. Inject context into LLM prompt
4. LLM generates OpenSearch DSL with proper field names & filters

**Result**: Accurate query targeting `event_id:4625`, `logon_type:3`, time filters

---

### Use Case 2: Event Analysis & Threat Hunting

**User Input**: "What is this suspicious PowerShell doing?"

**RAG Flow**:
1. Embed query → retrieve `sigma_powershell_obfuscation`, `mitre_T1059.001`
2. Context: Patterns explain encoded commands, reflection, download cradles
3. LLM analyzes event with patterns as reference
4. Answer: "This is **T1059.001 PowerShell execution** with base64 encoding (Sigma: powershell_base64_encoded_cmd). The command downloads a payload from..."

---

### Use Case 3: Auto-Hunt Generation

**User Marks Event as "Bad"**: `mimikatz.exe` execution

**RAG Flow**:
1. Embed event details → retrieve credential dumping patterns
2. Retrieved: `mitre_T1003`, `sigma_mimikatz`, `sigma_lsass_access`
3. LLM generates 5 hunt queries:
   - Same host ±15 min (what happened before/after?)
   - Same user on other hosts (lateral movement?)
   - LSASS process access across fleet (other credential dumps?)
   - Kerberos ticket requests (golden ticket usage?)
   - SMB/RDP connections from this host (where did they pivot?)

---

### Use Case 4: IOC Extraction

**User Input**: "Extract IOCs from this EDR report"

**RAG Flow**:
1. Embed report snippets → retrieve IOC-related patterns
2. Context: Examples of file paths, registry keys, C2 domains from rules
3. LLM extracts structured IOCs:
   - IPs: `192.168.1.100`, `10.0.0.5`
   - Domains: `evil[.]com`
   - Hashes: `d41d8cd98f00b204e9800998ecf8427e`
   - Registry: `HKLM\Software\Malware\Persistence`

---

### Use Case 5: General Threat Intel Chat

**User Input**: "Explain T1078.004"

**RAG Flow**:
1. Embed query → retrieve `mitre_T1078` (Valid Accounts)
2. Context includes sub-techniques (Cloud Accounts = T1078.004)
3. LLM explains: "T1078.004 is **Valid Accounts: Cloud Accounts**. Adversaries use stolen credentials to access cloud services. Detection: Monitor for unusual login patterns, MFA denials, access from new locations..."

---

## Technical Deep Dive

### Vector Dimensions: Why 384?

| Model | Dimensions | Speed | Quality | Use Case |
|-------|-----------|-------|---------|----------|
| all-MiniLM-L6-v2 | 384 | Fast | Good | General search (our choice) |
| bge-base-en-v1.5 | 768 | Medium | Better | High accuracy needed |
| OpenAI text-embedding-3-large | 3072 | Slow | Best | Production with GPU |

**Trade-offs**:
- More dims = better accuracy, slower search, more storage
- 384 dims = sweet spot for CPU inference + good accuracy

### HNSW Index Tuning

```sql
-- Default index (good for most cases)
CREATE INDEX ON pattern_embeddings 
USING HNSW (embedding vector_cosine_ops);

-- Tuned index (higher quality, slower build)
CREATE INDEX ON pattern_embeddings 
USING HNSW (embedding vector_cosine_ops)
WITH (m = 16, ef_construction = 64);
```

**Parameters**:
- `m` (default: 16) - Connections per node (higher = better recall, more memory)
- `ef_construction` (default: 64) - Build-time search quality (higher = slower build, better index)

**Query-time tuning**:
```sql
SET hnsw.ef_search = 40;  -- Default (higher = better recall, slower search)
```

### Embedding Model Performance

**On CPU (8-core)**:
- **Batch size 32**: ~500-800 texts/sec
- **Batch size 128**: ~1,000-1,500 texts/sec
- **Single text**: ~100ms latency

**On GPU (CUDA)**:
- **10x faster**: 5,000-10,000 texts/sec
- Requires ONNX Runtime GPU

**Memory**:
- Model: ~100 MB RAM
- Per pattern: ~1.5 KB (384 floats)
- 4,000 patterns: ~6 MB embeddings + index overhead

### Token Limits & Context Windows

**Ollama Qwen2.5 7B**:
- **Context window**: 32,768 tokens (~24,000 words)
- **Recommended max**: 4,096 tokens/request (faster inference)

**Token Budget** (typical query):
- System prompt: ~200 tokens
- Retrieved patterns (5): ~1,000 tokens (200 each)
- Events (50): ~2,000 tokens (40 each)
- User question: ~50 tokens
- **Total**: ~3,250 tokens (leaves ~800 for response)

**Why limit to 50 events?**:
- Prevents context overflow
- Faster inference (less tokens = less compute)
- Forces focus on most relevant events

---

## Performance Considerations

### Ingestion Performance

**3,765 patterns (Sigma + MITRE)**:
- **Parsing**: ~5 seconds
- **Embedding**: ~30-60 seconds (CPU)
- **Database insert**: ~10 seconds
- **Total**: ~1-2 minutes

**Re-ingestion**:
- Uses `ON CONFLICT DO NOTHING`
- Only inserts new patterns
- Safe to run repeatedly

### Query Performance

**Vector search (3,765 patterns)**:
- **Without index**: ~500ms (brute force)
- **With HNSW index**: ~5-10ms (50x faster)
- **Embedding query**: ~100ms (single text)
- **Total**: ~110-150ms (fast enough for real-time)

**Scalability**:
- **10,000 patterns**: Still <20ms search
- **100,000 patterns**: ~50-100ms search
- **1M+ patterns**: Consider sharding or filtering by source

### LLM Inference Performance

**Qwen2.5 7B (Q4_K_M quantization)**:

**On CPU (8-core, no GPU)**:
- **Prompt processing**: ~2-5 tokens/sec
- **Generation**: ~10-20 tokens/sec
- **200 token response**: ~10-20 seconds

**On GPU (8GB VRAM)**:
- **Prompt processing**: ~50-100 tokens/sec
- **Generation**: ~30-50 tokens/sec
- **200 token response**: ~4-7 seconds (3x faster)

**On GPU (16GB+ VRAM)**:
- **Prompt processing**: ~100-200 tokens/sec
- **Generation**: ~50-80 tokens/sec
- **200 token response**: ~2-4 seconds (5-10x faster)

---

## Troubleshooting

### Issue: "Patterns count is 0"

**Cause**: Ingestion script not run or failed

**Fix**:
```bash
cd /opt/casescope
source venv/bin/activate
python3 scripts/ingest_patterns.py
```

Check logs for errors (missing files, permission issues, etc.)

---

### Issue: "Vector search is slow"

**Cause**: HNSW index not created or query not using index

**Check**:
```sql
\d pattern_embeddings  -- Look for HNSW index
EXPLAIN ANALYZE 
SELECT * FROM pattern_embeddings 
ORDER BY embedding <=> '[0.1, 0.2, ...]'::vector 
LIMIT 5;
```

**Fix**: Rebuild index
```sql
DROP INDEX IF EXISTS pattern_embeddings_embedding_idx;
CREATE INDEX pattern_embeddings_embedding_idx 
ON pattern_embeddings USING HNSW (embedding vector_cosine_ops);
```

---

### Issue: "Low quality search results"

**Causes**:
1. Query too vague ("malware") vs specific ("lateral movement via RDP")
2. Patterns missing from corpus (need to ingest more rules)
3. Wrong embedding model (check `EMBEDDING_MODEL` in config)

**Fixes**:
- Test search in Python:
  ```python
  from app.ai.vector_store import PatternStore
  from app.config import VECTOR_STORE_CONFIG, EMBEDDING_MODEL
  
  store = PatternStore(VECTOR_STORE_CONFIG, EMBEDDING_MODEL)
  results = store.search("lateral movement", k=10)
  for r in results:
      print(f"{r['score']:.2f} - {r['id']} - {r['content'][:100]}")
  ```
- Increase `AI_RAG_TOP_K` from 5 to 10 (more context)
- Update Sigma rules: `cd /opt/casescope/data/sigma && git pull`

---

### Issue: "pgvector extension not found"

**Error**: `ERROR:  type "vector" does not exist`

**Fix**:
```bash
# Install pgvector
sudo apt update
sudo apt install postgresql-14-pgvector  # Adjust version

# Enable in database
sudo -u postgres psql casescope -c "CREATE EXTENSION vector;"
```

---

### Issue: "Embeddings fail with ONNX error"

**Cause**: Missing ONNX Runtime or CPU incompatibility

**Fix**:
```bash
source venv/bin/activate
pip install --upgrade onnxruntime fastembed
```

If CPU doesn't support AVX2:
```bash
pip install onnxruntime-openvino  # Alternative backend
```

---

## Summary

The RAG system is the **brain** of CaseScope's AI features, providing:

✅ **Semantic search** over 3,000+ Sigma rules & 600+ MITRE techniques  
✅ **Fast retrieval** (<10ms) using pgvector HNSW indexes  
✅ **Context injection** for LLM prompts (reduced hallucination)  
✅ **Always current** (update rules without retraining LLM)  
✅ **Fully local** (no external APIs, no data leakage)  

**Key Files**:
- `/opt/casescope/app/ai/vector_store.py` - Vector search implementation
- `/opt/casescope/app/ai/llm_client.py` - LLM + RAG integration
- `/opt/casescope/scripts/ingest_patterns.py` - Pattern ingestion
- `/opt/casescope/migrations/add_pgvector_patterns.sql` - Database schema

**Next Steps**:
- Monitor `pattern_embeddings` table size (should stay <50MB for 10K patterns)
- Update Sigma rules monthly: `cd /opt/casescope/data/sigma && git pull`
- Experiment with `AI_RAG_TOP_K` (3-10) to balance context vs speed
- Consider GPU for faster inference (3-10x speedup)

---

**Questions?** Check logs: `/opt/casescope/logs/celery_worker.log`

