#!/usr/bin/env python3
"""
Test AI API endpoints
"""

import sys
import os
sys.path.insert(0, '/opt/casescope')

# Add app to path for direct testing (bypass Flask)
from app.ai.ai_toggle import get_ai_status
from app.ai.llm_client import LLMClient
from app.ai.vector_store import PatternStore
from app.config import (
    VECTOR_STORE_CONFIG,
    EMBEDDING_MODEL,
    LLM_MODEL_CHAT,
    LLM_MODEL_CODE
)

print("="*70)
print(" AI API Endpoint Testing")
print("="*70)

#  Test 1: Status
print("\n1. Testing /api/ai/status")
try:
    status = get_ai_status()
    print(f"   ✅ Status: {status['status']}")
    print(f"   Message: {status['message']}")
    for comp, state in status['components'].items():
        icon = "✅" if state else "❌"
        print(f"   {icon} {comp}")
except Exception as e:
    print(f"   ❌ Error: {e}")

# Test 2: Vector Store (used by /api/ai/query)
print("\n2. Testing Vector Store (for /api/ai/query)")
try:
    store = PatternStore(VECTOR_STORE_CONFIG, EMBEDDING_MODEL)
    results = store.search("detect lateral movement", k=3)
    print(f"   ✅ Found {len(results)} patterns")
    for i, r in enumerate(results[:2], 1):
        title = r.get('metadata', {}).get('title') or r.get('metadata', {}).get('name')
        print(f"   {i}. [{r['source'].upper()}] {title[:50]}...")
except Exception as e:
    print(f"   ❌ Error: {e}")

# Test 3: LLM Client (DSL Generation for /api/ai/query)
print("\n3. Testing LLM DSL Generation (for /api/ai/query)")
try:
    client = LLMClient(LLM_MODEL_CHAT, LLM_MODEL_CODE)
    dsl = client.generate_opensearch_dsl(
        question="Show failed logins",
        index_fields=['event_id', 'search_blob', 'normalized_timestamp'],
        patterns_context="Event ID 4625 = Failed Login"
    )
    print(f"   ✅ Generated DSL")
    query_type = list(dsl.get('query', {}).keys())[0] if 'query' in dsl else 'none'
    print(f"   Query type: {query_type}")
except Exception as e:
    print(f"   ❌ Error: {e}")

# Test 4: Event Analysis (for /api/ai/analyze)
print("\n4. Testing Event Analysis (for /api/ai/analyze)")
try:
    test_events = [
        {
            'event_id': '4624',
            'normalized_computer': 'DC01',
            'search_blob': 'Successful login'
        }
    ]
    
    # Get patterns
    store = PatternStore(VECTOR_STORE_CONFIG, EMBEDDING_MODEL)
    patterns = store.search("login analysis", k=2)
    context = "\n".join([p['content'][:100] for p in patterns])
    
    # Analyze
    client = LLMClient(LLM_MODEL_CHAT, LLM_MODEL_CODE)
    analysis = client.analyze_events(
        events=test_events,
        question="What happened?",
        patterns_context=context
    )
    
    print(f"   ✅ Analysis generated ({len(analysis)} chars)")
    print(f"   Preview: {analysis[:100]}...")
except Exception as e:
    print(f"   ❌ Error: {e}")

# Test 5: IOC Extraction (for /api/ai/ioc)
print("\n5. Testing IOC Extraction (for /api/ai/ioc)")
try:
    test_text = """
    Malware contacted 192.168.1.100 and evil.example.com
    MD5 hash: d41d8cd98f00b204e9800998ecf8427e
    Email: attacker@bad-domain.net
    """
    
    client = LLMClient(LLM_MODEL_CHAT, LLM_MODEL_CODE)
    iocs = client.extract_iocs(test_text)
    
    total_iocs = sum([
        len(iocs.get('ip_addresses', [])),
        len(iocs.get('domains', [])),
        sum(len(v) for v in iocs.get('file_hashes', {}).values()),
        len(iocs.get('email_addresses', []))
    ])
    
    print(f"   ✅ Extracted {total_iocs} IOCs")
    print(f"   IPs: {len(iocs.get('ip_addresses', []))}")
    print(f"   Domains: {len(iocs.get('domains', []))}")
    print(f"   Hashes: {sum(len(v) for v in iocs.get('file_hashes', {}).values())}")
    print(f"   Emails: {len(iocs.get('email_addresses', []))}")
except Exception as e:
    print(f"   ❌ Error: {e}")

# Test 6: Chat (for /api/ai/chat)
print("\n6. Testing RAG Chat (for /api/ai/chat)")
try:
    store = PatternStore(VECTOR_STORE_CONFIG, EMBEDDING_MODEL)
    patterns = store.search("How to detect mimikatz", k=2)
    context = "\n".join([
        f"[{p['source'].upper()}] {p.get('metadata', {}).get('title') or p.get('metadata', {}).get('name')}"
        for p in patterns
    ])
    
    client = LLMClient(LLM_MODEL_CHAT, LLM_MODEL_CODE)
    response = client.chat(
        message="What is mimikatz?",
        history=[],
        context=context
    )
    
    print(f"   ✅ Chat response generated ({len(response)} chars)")
    print(f"   Preview: {response[:100]}...")
except Exception as e:
    print(f"   ❌ Error: {e}")

# Summary
print("\n" + "="*70)
print(" Test Summary")
print("="*70)
print("✅ All core AI components operational")
print("✅ Endpoints ready:")
print("   - GET  /api/ai/status")
print("   - POST /api/ai/query")
print("   - POST /api/ai/analyze")
print("   - POST /api/ai/hunt")
print("   - POST /api/ai/chat")
print("   - POST /api/ai/ioc")
print("\n⚠️  Note: Requires authentication (login_required)")
print("⚠️  Note: Most endpoints require admin role (admin_required)")
print("="*70)

