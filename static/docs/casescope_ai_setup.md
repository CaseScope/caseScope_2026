# Task: Add AI-Powered Threat Hunting Layer to CaseScope

## Overview
Add an AI layer to CaseScope for:
1. Natural language queries → OpenSearch DSL
2. Auto-hunting around tagged bad events
3. RAG-powered chat using Sigma rules as knowledge base
4. IOC extraction from events

## System Context
- Existing Flask app with OpenSearch backend
- Events indexed per case as `case_{case_id}`
- Tesla P4 GPU (8GB VRAM) available for inference
- Celery for background tasks

---

## Step 1: Dependencies

Add to requirements.txt:
```
ollama
chromadb
fastembed
pyyaml
```

---

## Step 2: Download and Setup Script

Create `scripts/setup_ai.sh`:

```bash
#!/bin/bash
set -e

echo "=== CaseScope AI Setup ==="

# 1. Install Ollama
if ! command -v ollama &> /dev/null; then
    echo "Installing Ollama..."
    curl -fsSL https://ollama.com/install.sh | sh
fi

# 2. Pull models (Q4_K_M quantization for 8GB VRAM)
echo "Pulling LLM models..."
ollama pull qwen2.5:7b-instruct-q4_K_M
ollama pull qwen2.5-coder:7b-instruct-q4_K_M

# 3. Create directories
echo "Creating directories..."
mkdir -p /opt/casescope/data/chromadb
mkdir -p /opt/casescope/data/sigma

# 4. Download Sigma rules
echo "Downloading Sigma rules..."
if [ ! -d "/opt/casescope/data/sigma/sigma" ]; then
    git clone --depth 1 https://github.com/SigmaHQ/sigma.git /opt/casescope/data/sigma/sigma
else
    cd /opt/casescope/data/sigma/sigma && git pull
fi

# 5. Download MITRE ATT&CK data
echo "Downloading MITRE ATT&CK..."
curl -s https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json \
    -o /opt/casescope/data/sigma/mitre_attack.json

echo "=== Setup Complete ==="
echo "Run 'python scripts/ingest_patterns.py' to populate vector store"
```

---

## Step 3: AI Configuration

Add to `app/config.py`:

```python
# ============================================================================
# AI / LLM SETTINGS
# ============================================================================

# Ollama connection
OLLAMA_HOST = 'http://localhost:11434'

# Models
LLM_MODEL_CHAT = 'qwen2.5:7b-instruct-q4_K_M'      # Chat and analysis
LLM_MODEL_CODE = 'qwen2.5-coder:7b-instruct-q4_K_M' # DSL generation

# Embedding model (runs on CPU via FastEmbed)
EMBEDDING_MODEL = 'BAAI/bge-small-en-v1.5'

# ChromaDB path
CHROMADB_PATH = '/opt/casescope/data/chromadb'

# Sigma rules path
SIGMA_RULES_PATH = '/opt/casescope/data/sigma/sigma/rules'
MITRE_ATTACK_PATH = '/opt/casescope/data/sigma/mitre_attack.json'

# AI query settings
AI_MAX_CONTEXT_EVENTS = 50  # Max events to include in LLM context
AI_RAG_TOP_K = 5            # Number of patterns to retrieve
```

---

## Step 4: Vector Store Module

Create `app/ai/__init__.py`:
```python
```

Create `app/ai/vector_store.py`:

```python
"""
Vector store for attack patterns using ChromaDB + FastEmbed
"""

import os
import yaml
import json
import logging
from pathlib import Path
from typing import List, Dict, Optional
import chromadb
from fastembed import TextEmbedding

logger = logging.getLogger(__name__)


class PatternStore:
    """
    Stores and retrieves attack patterns for RAG
    """
    
    def __init__(self, persist_dir: str, embedding_model: str = "BAAI/bge-small-en-v1.5"):
        self.client = chromadb.PersistentClient(path=persist_dir)
        self.collection = self.client.get_or_create_collection(
            name="attack_patterns",
            metadata={"hnsw:space": "cosine"}
        )
        self.embedder = TextEmbedding(model_name=embedding_model)
        logger.info(f"PatternStore initialized with {self.collection.count()} patterns")
    
    def _embed(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings for texts"""
        return list(self.embedder.embed(texts))
    
    def add_sigma_rules(self, rules_dir: str) -> int:
        """
        Ingest Sigma rules from directory
        
        Returns: Number of rules ingested
        """
        rules_path = Path(rules_dir)
        if not rules_path.exists():
            logger.error(f"Sigma rules directory not found: {rules_dir}")
            return 0
        
        documents = []
        metadatas = []
        ids = []
        
        for yaml_file in rules_path.rglob("*.yml"):
            try:
                with open(yaml_file, 'r', encoding='utf-8') as f:
                    rule = yaml.safe_load(f)
                
                if not rule or not isinstance(rule, dict):
                    continue
                
                # Build searchable text
                title = rule.get('title', '')
                description = rule.get('description', '')
                tags = rule.get('tags', [])
                level = rule.get('level', '')
                detection = yaml.dump(rule.get('detection', {}))
                
                # Format for embedding
                doc_text = f"""
Title: {title}
Description: {description}
Level: {level}
Tags: {', '.join(tags) if tags else 'none'}
Detection Logic:
{detection}
""".strip()
                
                documents.append(doc_text)
                metadatas.append({
                    'source': 'sigma',
                    'title': title,
                    'level': level,
                    'tags': ','.join(tags) if tags else '',
                    'file': str(yaml_file.name)
                })
                ids.append(f"sigma_{yaml_file.stem}")
                
            except Exception as e:
                logger.warning(f"Failed to parse {yaml_file}: {e}")
                continue
        
        if documents:
            # Batch embed and add
            embeddings = self._embed(documents)
            self.collection.add(
                documents=documents,
                embeddings=embeddings,
                metadatas=metadatas,
                ids=ids
            )
            logger.info(f"Ingested {len(documents)} Sigma rules")
        
        return len(documents)
    
    def add_mitre_attack(self, json_path: str) -> int:
        """
        Ingest MITRE ATT&CK techniques
        
        Returns: Number of techniques ingested
        """
        if not os.path.exists(json_path):
            logger.error(f"MITRE ATT&CK file not found: {json_path}")
            return 0
        
        with open(json_path, 'r') as f:
            attack_data = json.load(f)
        
        documents = []
        metadatas = []
        ids = []
        
        for obj in attack_data.get('objects', []):
            if obj.get('type') != 'attack-pattern':
                continue
            
            technique_id = ''
            for ref in obj.get('external_references', []):
                if ref.get('source_name') == 'mitre-attack':
                    technique_id = ref.get('external_id', '')
                    break
            
            if not technique_id:
                continue
            
            name = obj.get('name', '')
            description = obj.get('description', '')[:1000]  # Truncate
            tactics = [phase.get('phase_name', '') for phase in obj.get('kill_chain_phases', [])]
            
            doc_text = f"""
MITRE ATT&CK Technique: {technique_id} - {name}
Tactics: {', '.join(tactics)}
Description: {description}
""".strip()
            
            documents.append(doc_text)
            metadatas.append({
                'source': 'mitre',
                'technique_id': technique_id,
                'name': name,
                'tactics': ','.join(tactics)
            })
            ids.append(f"mitre_{technique_id}")
        
        if documents:
            embeddings = self._embed(documents)
            self.collection.add(
                documents=documents,
                embeddings=embeddings,
                metadatas=metadatas,
                ids=ids
            )
            logger.info(f"Ingested {len(documents)} MITRE techniques")
        
        return len(documents)
    
    def search(self, query: str, k: int = 5, source_filter: Optional[str] = None) -> List[Dict]:
        """
        Search for relevant patterns
        
        Args:
            query: Search query
            k: Number of results
            source_filter: Optional filter ('sigma' or 'mitre')
        
        Returns: List of matching patterns with metadata
        """
        embedding = self._embed([query])[0]
        
        where_filter = None
        if source_filter:
            where_filter = {"source": source_filter}
        
        results = self.collection.query(
            query_embeddings=[embedding],
            n_results=k,
            where=where_filter,
            include=["documents", "metadatas", "distances"]
        )
        
        patterns = []
        for i in range(len(results['ids'][0])):
            patterns.append({
                'id': results['ids'][0][i],
                'content': results['documents'][0][i],
                'metadata': results['metadatas'][0][i],
                'score': 1 - results['distances'][0][i]  # Convert distance to similarity
            })
        
        return patterns
    
    def get_stats(self) -> Dict:
        """Get collection statistics"""
        return {
            'total_patterns': self.collection.count()
        }
```

---

## Step 5: LLM Client Module

Create `app/ai/llm_client.py`:

```python
"""
LLM client for Ollama
"""

import json
import logging
from typing import Optional, Dict, List
import ollama

logger = logging.getLogger(__name__)


class LLMClient:
    """
    Wrapper for Ollama LLM calls
    """
    
    def __init__(self, chat_model: str, code_model: str):
        self.chat_model = chat_model
        self.code_model = code_model
    
    def generate_opensearch_dsl(self, question: str, index_fields: List[str], 
                                 patterns_context: str = "") -> Dict:
        """
        Convert natural language question to OpenSearch DSL
        """
        prompt = f"""Convert this question to an OpenSearch DSL query.

Available fields in the index:
{', '.join(index_fields)}

Relevant attack patterns for context:
{patterns_context}

Question: {question}

Return ONLY valid JSON DSL query. No explanation, no markdown, just the JSON object.
The query should search the 'search_blob' field for text searches.
Use bool queries with must/should/must_not as appropriate.
For time ranges, use 'normalized_timestamp' field.
For specific hosts, use 'normalized_computer' field.
For event IDs, use 'normalized_event_id' field.
"""
        
        try:
            response = ollama.chat(
                model=self.code_model,
                messages=[{"role": "user", "content": prompt}],
                format="json"
            )
            return json.loads(response['message']['content'])
        except Exception as e:
            logger.error(f"DSL generation failed: {e}")
            # Fallback to simple query_string
            return {
                "query": {
                    "query_string": {
                        "query": question,
                        "fields": ["search_blob"],
                        "default_operator": "AND"
                    }
                }
            }
    
    def analyze_events(self, events: List[Dict], question: str, 
                       patterns_context: str = "") -> str:
        """
        Analyze events and answer questions about them
        """
        events_text = json.dumps(events[:50], indent=2, default=str)  # Limit context
        
        prompt = f"""You are a DFIR analyst. Analyze these events and answer the question.

Relevant attack patterns:
{patterns_context}

Events:
{events_text}

Question: {question}

Provide a clear, concise analysis. Reference specific events by timestamp or ID.
If you see indicators of attack techniques, name them with MITRE ATT&CK IDs.
"""
        
        response = ollama.chat(
            model=self.chat_model,
            messages=[{"role": "user", "content": prompt}]
        )
        return response['message']['content']
    
    def generate_hunt_queries(self, bad_event: Dict, patterns_context: str) -> List[Dict]:
        """
        Generate hunt queries based on a known bad event
        """
        prompt = f"""You are a threat hunter. Given this malicious event, generate OpenSearch DSL queries to find related activity.

Known bad event:
{json.dumps(bad_event, indent=2, default=str)}

Relevant attack patterns:
{patterns_context}

Generate 5 hunt queries for:
1. Same host, ±15 minute time window
2. Same user (if present), any host, ±1 hour  
3. Similar process/command patterns across all hosts
4. Parent/child process relationships
5. Network connections or lateral movement indicators

Return a JSON array of objects with 'description' and 'dsl' keys.
"""
        
        try:
            response = ollama.chat(
                model=self.code_model,
                messages=[{"role": "user", "content": prompt}],
                format="json"
            )
            result = json.loads(response['message']['content'])
            if isinstance(result, list):
                return result
            elif isinstance(result, dict) and 'queries' in result:
                return result['queries']
            return []
        except Exception as e:
            logger.error(f"Hunt query generation failed: {e}")
            return []
    
    def extract_iocs(self, text: str) -> Dict:
        """
        Extract IOCs from text
        """
        prompt = f"""Extract all IOCs from this text. Return ONLY valid JSON with these keys:
- ip_addresses (array)
- domains (array)
- urls (array)
- file_hashes (object with md5, sha1, sha256 arrays)
- email_addresses (array)
- file_names (array)
- registry_keys (array)
- cve_ids (array)

Defang indicators where appropriate (e.g., example[.]com).
No duplicates. Empty arrays for categories with no findings.

Text:
{text}
"""
        
        try:
            response = ollama.chat(
                model=self.chat_model,
                messages=[{"role": "user", "content": prompt}],
                format="json"
            )
            return json.loads(response['message']['content'])
        except Exception as e:
            logger.error(f"IOC extraction failed: {e}")
            return {
                "ip_addresses": [],
                "domains": [],
                "urls": [],
                "file_hashes": {"md5": [], "sha1": [], "sha256": []},
                "email_addresses": [],
                "file_names": [],
                "registry_keys": [],
                "cve_ids": []
            }
    
    def chat(self, message: str, history: List[Dict], context: str = "") -> str:
        """
        General chat with conversation history
        """
        system_prompt = f"""You are a DFIR assistant for CaseScope. Help analysts investigate security events.
You have access to attack patterns and can help interpret events.

Available context:
{context}

Be concise and technical. Reference MITRE ATT&CK when relevant.
"""
        
        messages = [{"role": "system", "content": system_prompt}]
        messages.extend(history[-10:])  # Last 10 messages
        messages.append({"role": "user", "content": message})
        
        response = ollama.chat(
            model=self.chat_model,
            messages=messages
        )
        return response['message']['content']
```

---

## Step 6: AI Routes

Create `app/routes/ai.py`:

```python
"""
AI Routes
Natural language queries, auto-hunting, and RAG chat
"""

from flask import Blueprint, jsonify, request, session
from flask_login import login_required, current_user
from opensearchpy import OpenSearch
import logging
import json

logger = logging.getLogger(__name__)

ai_bp = Blueprint('ai', __name__, url_prefix='/ai')

# Lazy-loaded singletons
_pattern_store = None
_llm_client = None


def get_pattern_store():
    global _pattern_store
    if _pattern_store is None:
        from app.config import CHROMADB_PATH, EMBEDDING_MODEL
        from app.ai.vector_store import PatternStore
        _pattern_store = PatternStore(CHROMADB_PATH, EMBEDDING_MODEL)
    return _pattern_store


def get_llm_client():
    global _llm_client
    if _llm_client is None:
        from app.config import LLM_MODEL_CHAT, LLM_MODEL_CODE
        from app.ai.llm_client import LLMClient
        _llm_client = LLMClient(LLM_MODEL_CHAT, LLM_MODEL_CODE)
    return _llm_client


def get_opensearch_client():
    from app.config import Config
    return OpenSearch(
        hosts=[{'host': Config.OPENSEARCH_HOST, 'port': Config.OPENSEARCH_PORT}],
        use_ssl=Config.OPENSEARCH_USE_SSL,
        verify_certs=False,
        ssl_show_warn=False,
        timeout=30
    )


def verify_case_access(case_id):
    """Verify user has access to case"""
    from models import Case
    case = Case.query.get(case_id)
    if not case:
        return None, "Case not found"
    if current_user.role == 'read-only' and case.id != current_user.case_assigned:
        return None, "Access denied"
    return case, None


@ai_bp.route('/query', methods=['POST'])
@login_required
def nl_query():
    """
    Convert natural language to OpenSearch query and execute
    
    POST body:
    {
        "question": "Show me failed logins from user admin"
    }
    """
    try:
        case_id = session.get('selected_case_id')
        if not case_id:
            return jsonify({'error': 'No case selected'}), 400
        
        case, error = verify_case_access(case_id)
        if error:
            return jsonify({'error': error}), 403
        
        question = request.json.get('question', '').strip()
        if not question:
            return jsonify({'error': 'No question provided'}), 400
        
        # Get relevant patterns from RAG
        patterns = get_pattern_store().search(question, k=3)
        patterns_context = "\n\n".join([p['content'] for p in patterns])
        
        # Define available fields
        index_fields = [
            'search_blob', 'normalized_timestamp', 'normalized_computer',
            'normalized_event_id', 'event_id', 'channel', 'provider_name',
            'process.name', 'process.command_line', 'user.name', 'source_file'
        ]
        
        # Generate DSL
        dsl = get_llm_client().generate_opensearch_dsl(question, index_fields, patterns_context)
        
        # Execute query
        client = get_opensearch_client()
        index_name = f"case_{case_id}"
        
        # Add size limit
        if 'size' not in dsl:
            dsl['size'] = 100
        
        response = client.search(index=index_name, body=dsl)
        
        events = []
        for hit in response['hits']['hits']:
            events.append({
                'id': hit['_id'],
                'source': hit['_source']
            })
        
        return jsonify({
            'question': question,
            'dsl': dsl,
            'total': response['hits']['total']['value'],
            'events': events,
            'patterns_used': [p['metadata'].get('title', p['id']) for p in patterns]
        })
        
    except Exception as e:
        logger.error(f"NL query error: {e}")
        return jsonify({'error': str(e)}), 500


@ai_bp.route('/hunt', methods=['POST'])
@login_required
def auto_hunt():
    """
    Generate and execute hunt queries based on a known bad event
    
    POST body:
    {
        "event_id": "abc123"
    }
    """
    try:
        case_id = session.get('selected_case_id')
        if not case_id:
            return jsonify({'error': 'No case selected'}), 400
        
        case, error = verify_case_access(case_id)
        if error:
            return jsonify({'error': error}), 403
        
        event_id = request.json.get('event_id')
        if not event_id:
            return jsonify({'error': 'No event_id provided'}), 400
        
        # Get the bad event
        client = get_opensearch_client()
        index_name = f"case_{case_id}"
        
        bad_event = client.get(index=index_name, id=event_id)['_source']
        
        # Get relevant patterns
        event_summary = json.dumps(bad_event, default=str)[:2000]
        patterns = get_pattern_store().search(event_summary, k=5)
        patterns_context = "\n\n".join([p['content'] for p in patterns])
        
        # Generate hunt queries
        hunt_queries = get_llm_client().generate_hunt_queries(bad_event, patterns_context)
        
        # Execute each hunt query
        results = []
        for hq in hunt_queries:
            try:
                dsl = hq.get('dsl', {})
                if not dsl:
                    continue
                dsl['size'] = 50  # Limit results per query
                
                response = client.search(index=index_name, body=dsl)
                
                results.append({
                    'description': hq.get('description', 'Hunt query'),
                    'dsl': dsl,
                    'total': response['hits']['total']['value'],
                    'events': [{'id': h['_id'], 'source': h['_source']} 
                              for h in response['hits']['hits']]
                })
            except Exception as e:
                logger.warning(f"Hunt query failed: {e}")
                results.append({
                    'description': hq.get('description', 'Hunt query'),
                    'error': str(e)
                })
        
        return jsonify({
            'bad_event': bad_event,
            'hunt_results': results,
            'patterns_used': [p['metadata'].get('title', p['id']) for p in patterns]
        })
        
    except Exception as e:
        logger.error(f"Auto-hunt error: {e}")
        return jsonify({'error': str(e)}), 500


@ai_bp.route('/analyze', methods=['POST'])
@login_required
def analyze_events():
    """
    Analyze events and answer a question
    
    POST body:
    {
        "event_ids": ["id1", "id2"],
        "question": "What attack technique is this?"
    }
    """
    try:
        case_id = session.get('selected_case_id')
        if not case_id:
            return jsonify({'error': 'No case selected'}), 400
        
        case, error = verify_case_access(case_id)
        if error:
            return jsonify({'error': error}), 403
        
        event_ids = request.json.get('event_ids', [])
        question = request.json.get('question', 'What do these events indicate?')
        
        if not event_ids:
            return jsonify({'error': 'No event_ids provided'}), 400
        
        # Fetch events
        client = get_opensearch_client()
        index_name = f"case_{case_id}"
        
        events = []
        for eid in event_ids[:50]:  # Limit to 50
            try:
                event = client.get(index=index_name, id=eid)['_source']
                events.append(event)
            except:
                continue
        
        if not events:
            return jsonify({'error': 'No events found'}), 404
        
        # Get patterns
        events_text = json.dumps(events, default=str)[:3000]
        patterns = get_pattern_store().search(events_text, k=5)
        patterns_context = "\n\n".join([p['content'] for p in patterns])
        
        # Analyze
        analysis = get_llm_client().analyze_events(events, question, patterns_context)
        
        return jsonify({
            'question': question,
            'analysis': analysis,
            'events_analyzed': len(events),
            'patterns_used': [p['metadata'].get('title', p['id']) for p in patterns]
        })
        
    except Exception as e:
        logger.error(f"Analysis error: {e}")
        return jsonify({'error': str(e)}), 500


@ai_bp.route('/chat', methods=['POST'])
@login_required
def chat():
    """
    RAG-powered chat
    
    POST body:
    {
        "message": "What does event 4624 with logon type 9 mean?",
        "history": [{"role": "user", "content": "..."}, {"role": "assistant", "content": "..."}]
    }
    """
    try:
        message = request.json.get('message', '').strip()
        history = request.json.get('history', [])
        
        if not message:
            return jsonify({'error': 'No message provided'}), 400
        
        # Get relevant patterns
        patterns = get_pattern_store().search(message, k=5)
        context = "\n\n".join([p['content'] for p in patterns])
        
        # Chat
        response = get_llm_client().chat(message, history, context)
        
        return jsonify({
            'response': response,
            'patterns_used': [p['metadata'].get('title', p['id']) for p in patterns]
        })
        
    except Exception as e:
        logger.error(f"Chat error: {e}")
        return jsonify({'error': str(e)}), 500


@ai_bp.route('/extract-iocs', methods=['POST'])
@login_required
def extract_iocs():
    """
    Extract IOCs from text or events
    
    POST body:
    {
        "text": "The attacker used IP 192.168.1.100..."
    }
    OR
    {
        "event_ids": ["id1", "id2"]
    }
    """
    try:
        text = request.json.get('text', '')
        event_ids = request.json.get('event_ids', [])
        
        if event_ids:
            case_id = session.get('selected_case_id')
            if not case_id:
                return jsonify({'error': 'No case selected'}), 400
            
            case, error = verify_case_access(case_id)
            if error:
                return jsonify({'error': error}), 403
            
            client = get_opensearch_client()
            index_name = f"case_{case_id}"
            
            events = []
            for eid in event_ids[:20]:
                try:
                    event = client.get(index=index_name, id=eid)['_source']
                    events.append(event)
                except:
                    continue
            
            text = json.dumps(events, default=str)
        
        if not text:
            return jsonify({'error': 'No text or event_ids provided'}), 400
        
        iocs = get_llm_client().extract_iocs(text)
        
        return jsonify({'iocs': iocs})
        
    except Exception as e:
        logger.error(f"IOC extraction error: {e}")
        return jsonify({'error': str(e)}), 500


@ai_bp.route('/status')
@login_required
def status():
    """Check AI system status"""
    try:
        # Check pattern store
        store = get_pattern_store()
        stats = store.get_stats()
        
        # Check Ollama
        ollama_status = "unknown"
        try:
            import ollama
            models = ollama.list()
            ollama_status = "connected"
        except:
            ollama_status = "disconnected"
        
        return jsonify({
            'status': 'ok',
            'pattern_store': stats,
            'ollama': ollama_status
        })
        
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500
```

---

## Step 7: Pattern Ingestion Script

Create `scripts/ingest_patterns.py`:

```python
#!/usr/bin/env python3
"""
Ingest Sigma rules and MITRE ATT&CK into ChromaDB
"""

import sys
import os

# Add app to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import CHROMADB_PATH, SIGMA_RULES_PATH, MITRE_ATTACK_PATH, EMBEDDING_MODEL
from app.ai.vector_store import PatternStore


def main():
    print("=== Pattern Ingestion ===")
    
    store = PatternStore(CHROMADB_PATH, EMBEDDING_MODEL)
    
    # Check current count
    stats = store.get_stats()
    print(f"Current patterns in store: {stats['total_patterns']}")
    
    # Ingest Sigma rules
    print(f"\nIngesting Sigma rules from: {SIGMA_RULES_PATH}")
    sigma_count = store.add_sigma_rules(SIGMA_RULES_PATH)
    print(f"Ingested {sigma_count} Sigma rules")
    
    # Ingest MITRE ATT&CK
    print(f"\nIngesting MITRE ATT&CK from: {MITRE_ATTACK_PATH}")
    mitre_count = store.add_mitre_attack(MITRE_ATTACK_PATH)
    print(f"Ingested {mitre_count} MITRE techniques")
    
    # Final stats
    stats = store.get_stats()
    print(f"\n=== Complete ===")
    print(f"Total patterns in store: {stats['total_patterns']}")


if __name__ == '__main__':
    main()
```

---

## Step 8: Register Blueprint

In `app/main.py`, add:

```python
from app.routes.ai import ai_bp
app.register_blueprint(ai_bp)
```

---

## Step 9: Ollama Systemd Service (Optional)

Create `/etc/systemd/system/ollama.service`:

```ini
[Unit]
Description=Ollama LLM Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/ollama serve
Restart=always
RestartSec=3
Environment="OLLAMA_HOST=0.0.0.0"

[Install]
WantedBy=multi-user.target
```

Enable: `systemctl enable --now ollama`

---

## Summary of Files to Create

```
app/
├── ai/
│   ├── __init__.py
│   ├── vector_store.py
│   └── llm_client.py
├── routes/
│   └── ai.py (new)
scripts/
├── setup_ai.sh (new)
└── ingest_patterns.py (new)
```

## Models Used

| Purpose | Model | Quantization |
|---------|-------|--------------|
| Chat/Analysis | qwen2.5:7b-instruct | Q4_K_M |
| DSL Generation | qwen2.5-coder:7b-instruct | Q4_K_M |
| Embeddings | BAAI/bge-small-en-v1.5 | - (CPU) |

---

## API Endpoints Summary

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/ai/query` | POST | Natural language → OpenSearch query |
| `/ai/hunt` | POST | Auto-hunt from known bad event |
| `/ai/analyze` | POST | Analyze events with LLM |
| `/ai/chat` | POST | RAG-powered chat |
| `/ai/extract-iocs` | POST | Extract IOCs from text/events |
| `/ai/status` | GET | Check AI system status |
