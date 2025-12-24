# CaseScope AI API Documentation

## Overview

The AI API provides intelligent threat hunting, event analysis, and IOC extraction capabilities using local LLMs (Ollama) with RAG (Retrieval Augmented Generation) backed by PostgreSQL + pgvector.

**Base URL:** `https://your-casescope-server`

**Authentication:** All endpoints require authentication. Most require admin role.

**Toggle:** Can be disabled with `AI_ENABLED=False` in `config.py`

---

## Endpoints

### 1. GET /api/ai/status

Get AI system status and component health.

**Authentication:** Login required  
**Role:** Any authenticated user

**Response:**
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

**Status Values:**
- `operational` - All components healthy
- `degraded` - Some components unavailable
- `disabled` - AI disabled in config

---

### 2. POST /api/ai/query

Convert natural language question to OpenSearch query and execute.

**Authentication:** Login required  
**Role:** Administrator

**Request:**
```json
{
  "question": "Show me failed login attempts from the last 24 hours",
  "case_id": 123,     // Optional: filter to specific case
  "limit": 50         // Optional: max events (default 50, max 50)
}
```

**Response:**
```json
{
  "success": true,
  "question": "Show me failed login attempts from the last 24 hours",
  "dsl_query": {
    "query": {
      "bool": {
        "must": [...]
      }
    },
    "size": 50
  },
  "patterns_used": [
    {
      "id": "sigma_failed_login",
      "source": "sigma",
      "title": "Failed Login Detection",
      "score": 0.85
    }
  ],
  "events": [...],
  "event_count": 42,
  "total_hits": 156,
  "execution_time_ms": 1234.56
}
```

**Example Usage:**
```python
import requests

response = requests.post(
    'https://casescope/api/ai/query',
    json={'question': 'Find suspicious PowerShell executions'},
    verify=False
)
```

---

### 3. POST /api/ai/analyze

Analyze events using AI with RAG context.

**Authentication:** Login required  
**Role:** Administrator

**Request:**
```json
{
  "events": [
    {
      "event_id": "4624",
      "normalized_computer": "DC01",
      "normalized_timestamp": "2025-12-23T10:00:00Z",
      "search_blob": "Login successful for user admin..."
    }
  ],
  "question": "What happened here?",  // Optional
  "context": "User reported suspicious activity"  // Optional
}
```

**Response:**
```json
{
  "success": true,
  "analysis": "The events show a successful login (Event ID 4624) to domain controller DC01 by the admin account. This occurred at 10:00 AM UTC...",
  "patterns_referenced": [
    {
      "id": "mitre_T1078",
      "source": "mitre",
      "title": "Valid Accounts",
      "score": 0.78
    }
  ],
  "event_count": 1
}
```

---

### 4. POST /api/ai/hunt

Generate threat hunting queries based on a known malicious event.

**Authentication:** Login required  
**Role:** Administrator

**Request:**
```json
{
  "event": {
    "event_id": "4688",
    "normalized_computer": "WS001",
    "normalized_username": "attacker",
    "search_blob": "Process creation: mimikatz.exe"
  },
  "hunt_scope": "all"  // "host", "user", "network", "all"
}
```

**Response:**
```json
{
  "success": true,
  "hunt_queries": [
    {
      "description": "Find all activity from same host ±15 minutes",
      "dsl": {
        "query": {
          "bool": {
            "must": [...]
          }
        }
      },
      "rationale": "Identify related events on compromised system"
    },
    {
      "description": "Find same user activity across all hosts",
      "dsl": {...},
      "rationale": "Track lateral movement"
    }
  ],
  "patterns_used": [...]
}
```

---

### 5. POST /api/ai/chat

Chat with AI assistant using RAG for contextual responses.

**Authentication:** Login required  
**Role:** Administrator

**Request:**
```json
{
  "message": "How can I detect credential dumping?",
  "history": [
    {"role": "user", "content": "What is mimikatz?"},
    {"role": "assistant", "content": "Mimikatz is a tool..."}
  ],
  "context_events": [...]  // Optional: events for context
}
```

**Response:**
```json
{
  "success": true,
  "response": "To detect credential dumping, you should monitor for:\n\n1. Process access to LSASS (Event ID 10)\n2. Suspicious tools like mimikatz.exe...",
  "patterns_used": [
    {
      "id": "sigma_credential_dumping",
      "source": "sigma",
      "title": "Credential Dumping via LSASS",
      "score": 0.91
    }
  ]
}
```

---

### 6. POST /api/ai/ioc

Extract Indicators of Compromise from text or events.

**Authentication:** Login required  
**Role:** Any authenticated user

**Request:**
```json
{
  "text": "Malware contacted 192.168.1.100 and evil.example.com. MD5: d41d8cd98f00b204e9800998ecf8427e",
  "events": [...]  // Alternative to text
}
```

**Response:**
```json
{
  "success": true,
  "iocs": {
    "ip_addresses": ["192.168.1.100"],
    "domains": ["evil[.]example[.]com"],
    "urls": [],
    "file_hashes": {
      "md5": ["d41d8cd98f00b204e9800998ecf8427e"],
      "sha1": [],
      "sha256": []
    },
    "email_addresses": [],
    "file_names": [],
    "registry_keys": [],
    "cve_ids": []
  },
  "total_iocs": 3
}
```

---

## Error Responses

### AI Disabled
```json
{
  "error": "AI features not available",
  "reason": "AI disabled in config (AI_ENABLED=False)"
}
```
**Status Code:** 404

### AI Unavailable
```json
{
  "error": "AI features not available",
  "reason": "Ollama not accessible: Connection refused"
}
```
**Status Code:** 404

### Authentication Required
```
Redirects to login page
```
**Status Code:** 302

### Admin Required
```
Flash message: "Administrator access required"
Redirects to index
```
**Status Code:** 302

### Invalid Request
```json
{
  "error": "Question is required"
}
```
**Status Code:** 400

### Internal Error
```json
{
  "error": "AI query failed",
  "message": "detailed error message"
}
```
**Status Code:** 500

---

## Rate Limiting

Currently no rate limiting implemented. Recommended:
- 10 requests/minute per user for `/api/ai/query`
- 5 requests/minute per user for `/api/ai/analyze`
- 20 requests/minute per user for `/api/ai/chat`

---

## Performance

| Endpoint | Avg Response Time | Notes |
|----------|-------------------|-------|
| `/api/ai/status` | < 50ms | No LLM call |
| `/api/ai/query` | 3-8s | LLM + OpenSearch |
| `/api/ai/analyze` | 3-8s | LLM inference |
| `/api/ai/hunt` | 3-8s | LLM inference |
| `/api/ai/chat` | 3-8s | LLM inference |
| `/api/ai/ioc` | 2-5s | LLM inference |

**Hardware Impact:**
- 8GB GPU: 20-40 tokens/sec
- CPU only: 3-10 tokens/sec (10-30s response time)

---

## Audit Logging

All AI operations are logged to the audit log with:
- Action type (e.g., `ai_query`, `ai_analyze`)
- User who initiated
- Resource details
- Timestamp

**Example Audit Entry:**
```json
{
  "action": "ai_query",
  "user": "admin",
  "resource_type": "search",
  "resource_name": "AI Natural Language Query",
  "details": {
    "question": "Show failed logins",
    "event_count": 42,
    "patterns_used": 3
  },
  "timestamp": "2025-12-23T10:00:00Z"
}
```

---

## Configuration

In `/opt/casescope/app/config.py`:

```python
# Enable/Disable AI
AI_ENABLED = True
AI_AUTO_DETECT = True  # Auto-check if components available

# Models
LLM_MODEL_CHAT = 'qwen2.5:7b-instruct-q4_k_m'
LLM_MODEL_CODE = 'qwen2.5-coder:7b-instruct-q4_k_m'

# Limits
AI_MAX_CONTEXT_EVENTS = 50  # Max events in LLM context
AI_RAG_TOP_K = 5            # Patterns to retrieve from vector store
```

---

## Testing

### Test Script
```bash
cd /opt/casescope
sudo -u casescope /opt/casescope/venv/bin/python3 scripts/test_ai_endpoints.py
```

### Manual Test (requires login)
```bash
# Get session cookie first via browser, then:
curl -X POST 'https://casescope/api/ai/ioc' \
  -H 'Content-Type: application/json' \
  -H 'Cookie: session=YOUR_SESSION_COOKIE' \
  -d '{"text": "Malware at 192.168.1.100"}' \
  --insecure
```

---

## Examples

### Example 1: Natural Language Search
```python
import requests
from requests.auth import HTTPBasicAuth

# Login first (get session cookie)
session = requests.Session()
session.verify = False

# Query
response = session.post(
    'https://casescope/api/ai/query',
    json={
        'question': 'Find all PowerShell executions with encoded commands',
        'limit': 20
    }
)

data = response.json()
print(f"Found {data['event_count']} events")
for event in data['events']:
    print(f"- {event['normalized_timestamp']}: {event['event_id']}")
```

### Example 2: Event Analysis
```python
events = [
    {'event_id': '4624', 'normalized_computer': 'DC01'},
    {'event_id': '4625', 'normalized_computer': 'DC01'},
]

response = session.post(
    'https://casescope/api/ai/analyze',
    json={
        'events': events,
        'question': 'Is this a brute force attack?'
    }
)

print(response.json()['analysis'])
```

### Example 3: IOC Extraction
```python
text = """
Malware analysis report:
- C2 server: malware[.]evil[.]com (104.21.45.123)
- Dropper hash: 5d41402abc4b2a76b9719d911017c592
- Email: attacker@badguys.net
"""

response = session.post(
    'https://casescope/api/ai/ioc',
    json={'text': text}
)

iocs = response.json()['iocs']
print(f"IPs: {iocs['ip_addresses']}")
print(f"Domains: {iocs['domains']}")
print(f"Hashes: {iocs['file_hashes']['md5']}")
```

---

## Troubleshooting

### "AI features not available"
1. Check AI status: `python3 scripts/check_ai_availability.py`
2. Verify Ollama running: `systemctl status ollama`
3. Check models: `ollama list`
4. Verify vector store: `psql casescope -c "SELECT COUNT(*) FROM pattern_embeddings"`

### Slow responses
1. Check GPU usage: `nvidia-smi`
2. Consider smaller model for CPU: `qwen2.5:3b`
3. Reduce `AI_MAX_CONTEXT_EVENTS`

### Out of memory
1. Use smaller quantization: `q4_k_m` instead of `q5_k_m`
2. Reduce Ollama concurrent requests
3. Add swap space

---

## Security Considerations

1. **Admin-Only Access**: Most endpoints require administrator role
2. **Input Validation**: All user input is sanitized before LLM processing
3. **No Prompt Injection**: System prompts are protected
4. **Audit Logging**: All AI operations logged
5. **Rate Limiting**: Recommended for production (not implemented)
6. **HTTPS Only**: API should only be accessed over HTTPS

---

## Future Enhancements

- [ ] Rate limiting per user/role
- [ ] Async task processing for long queries
- [ ] Result caching for common questions
- [ ] Fine-tuned models for DFIR
- [ ] Multi-model support (switch between models)
- [ ] Custom pattern libraries per case
- [ ] AI-assisted report generation
- [ ] Automated threat briefings

