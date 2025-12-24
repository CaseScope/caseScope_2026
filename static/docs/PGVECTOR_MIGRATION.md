# PostgreSQL + pgvector Migration Complete ✅

## Summary

Successfully migrated from ChromaDB to **PostgreSQL + pgvector** for vector storage.

---

## What Changed

### 1. **Vector Storage Backend**
- ❌ **Old**: ChromaDB (file-based vector database)
- ✅ **New**: PostgreSQL with pgvector extension

### 2. **Benefits**
- ✅ Single database (PostgreSQL) for everything
- ✅ Simpler architecture (no separate ChromaDB service)
- ✅ Better integration with existing CaseScope data
- ✅ Unified backup/restore strategy
- ✅ No file permission issues
- ✅ Can join vector queries with relational data

---

## Database Schema

### New Table: `pattern_embeddings`

```sql
CREATE TABLE pattern_embeddings (
    id SERIAL PRIMARY KEY,
    pattern_id VARCHAR(200) UNIQUE NOT NULL,
    source VARCHAR(50) NOT NULL,  -- 'sigma' or 'mitre'
    content TEXT NOT NULL,
    embedding vector(384) NOT NULL,  -- 384-dim for BAAI/bge-small-en-v1.5
    metadata JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX pattern_embeddings_embedding_idx 
    ON pattern_embeddings USING hnsw (embedding vector_cosine_ops);
CREATE INDEX pattern_embeddings_source_idx ON pattern_embeddings (source);
CREATE INDEX pattern_embeddings_metadata_idx ON pattern_embeddings USING gin (metadata);
```

---

## Files Modified

### Configuration
- **`app/config.py`**: Changed `CHROMADB_PATH` to `VECTOR_STORE_CONFIG` (PostgreSQL connection params)
- **`requirements_ai.txt`**: Replaced `chromadb` with `psycopg2-binary` and `pgvector`

### Core Logic
- **`app/ai/vector_store.py`**: Complete rewrite to use PostgreSQL + pgvector
  - Uses `psycopg2` for database connection
  - Uses `pgvector` Python library for vector operations
  - Converts numpy float32 → Python float for psycopg2 compatibility

### Scripts
- **`scripts/setup_ai.sh`**: Updated to install pgvector and enable extension
- **`scripts/ingest_patterns.py`**: Updated to use new vector store config
- **`scripts/test_vector_search.py`**: Created for testing vector search

### Database
- **`migrations/add_pgvector_patterns.sql`**: New migration to create vector table

---

## Installation Status

✅ **pgvector extension**: Installed (v0.6.0)  
✅ **pattern_embeddings table**: Created  
✅ **Python dependencies**: Installed (`psycopg2-binary`, `pgvector`)  
✅ **Patterns ingested**: 3,918 total
  - 3,083 Sigma rules
  - 835 MITRE ATT&CK techniques

---

## Performance

### Vector Search Test Results

All test queries completed successfully with high-quality results:

- **Query**: "suspicious powershell execution"  
  **Top Result**: Suspicious PowerShell Download and Execute Pattern (Score: 0.8187)

- **Query**: "lateral movement with psexec"  
  **Top Result**: MMC20 Lateral Movement (Score: 0.7388)

- **Query**: "mimikatz credential dumping"  
  **Top Result**: Credential Dumping Attempt Via WerFault (Score: 0.8051)

- **Query**: "process injection techniques"  
  **Top Result**: MITRE T1055 - Process Injection (Score: 0.8167)

- **Query**: "command and control beaconing"  
  **Top Result**: MITRE T1001 - Data Obfuscation (Score: 0.7057)

**Source filtering** (Sigma vs MITRE) is working correctly.

---

## How It Works

### 1. **Ingestion** (`scripts/ingest_patterns.py`)
- Reads Sigma YAML rules and MITRE ATT&CK JSON
- Generates 384-dimensional embeddings using FastEmbed (CPU-based)
- Stores in PostgreSQL `pattern_embeddings` table

### 2. **Search** (`app/ai/vector_store.py`)
- Query text → embedding (FastEmbed)
- PostgreSQL cosine similarity search: `1 - (embedding <=> query_embedding)`
- Returns top-k most relevant patterns

### 3. **Index Type**
- Uses **HNSW index** (Hierarchical Navigable Small World)
- Fast approximate nearest neighbor search
- Optimized for cosine similarity

---

## Next Steps (From casescope_ai_setup.md)

### Phase 1 Complete ✅
- ✅ Install Ollama + LLM models
- ✅ Set up vector store (PostgreSQL + pgvector)
- ✅ Ingest Sigma rules + MITRE ATT&CK
- ✅ Test vector search

### Phase 2: Backend API (Next)
- Create `app/routes/ai.py` with endpoints:
  - `/api/ai/query` - Natural language → OpenSearch DSL
  - `/api/ai/analyze` - Event analysis
  - `/api/ai/hunt` - Auto-generate hunt queries
  - `/api/ai/chat` - RAG-powered chat
  - `/api/ai/ioc` - IOC extraction
- Register AI blueprint in `app/main.py`

### Phase 3: Frontend UI
- Add "AI Assistant" tile to dashboard
- Create modal/panel for AI interactions
- Display hunt queries, analysis, IOCs

---

## Maintenance

### Update Patterns
```bash
# Re-run ingestion to update with latest Sigma rules
cd /opt/casescope
sudo -u casescope /opt/casescope/venv/bin/python3 scripts/ingest_patterns.py
```

### Check Pattern Count
```sql
SELECT source, COUNT(*) 
FROM pattern_embeddings 
GROUP BY source;
```

### Test Vector Search
```bash
cd /opt/casescope
sudo -u casescope /opt/casescope/venv/bin/python3 scripts/test_vector_search.py
```

---

## Technical Notes

### Why pgvector?
- **Mature**: Battle-tested PostgreSQL extension
- **Fast**: HNSW index provides ~ms query times
- **Scalable**: Handles millions of vectors
- **Integrated**: No separate service needed

### Embedding Model
- **Model**: BAAI/bge-small-en-v1.5
- **Dimensions**: 384
- **Speed**: CPU-based (no GPU required)
- **Quality**: State-of-the-art for retrieval tasks

### Distance Metric
- **Cosine Similarity**: `1 - (embedding <=> query)`
- Values range from 0 (dissimilar) to 1 (identical)
- Scores > 0.7 are generally high-quality matches

---

**Migration completed successfully!** 🎉

