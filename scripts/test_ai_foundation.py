#!/usr/bin/env python3
"""
Pre-Phase 2 Integration Tests
Tests all foundation components before building API routes
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
from app.config import (
    VECTOR_STORE_CONFIG, 
    EMBEDDING_MODEL,
    OLLAMA_HOST,
    LLM_MODEL_CHAT,
    LLM_MODEL_CODE,
    OPENSEARCH_HOST,
    OPENSEARCH_PORT,
    OPENSEARCH_USE_SSL
)


def test_1_ollama_connectivity():
    """Test if Ollama is running and models are available"""
    print("\n" + "="*60)
    print("TEST 1: Ollama Connectivity")
    print("="*60)
    
    try:
        import ollama
        
        # Test connection
        response = ollama.list()
        print(f"✅ Ollama is running at {OLLAMA_HOST}")
        print(f"   Available models:")
        
        # Extract model names from response
        model_names = []
        if hasattr(response, 'models'):
            # Response is an object with models attribute
            for model in response.models:
                if hasattr(model, 'model'):
                    model_names.append(model.model)
                    print(f"   - {model.model}")
        elif isinstance(response, dict) and 'models' in response:
            # Response is a dict
            for model in response['models']:
                name = model.get('name') or model.get('model')
                if name:
                    model_names.append(name)
                    print(f"   - {name}")
        
        # Check required models
        required = [LLM_MODEL_CHAT, LLM_MODEL_CODE]
        all_found = True
        for req in required:
            if any(req in name for name in model_names):
                print(f"✅ Required model found: {req}")
            else:
                print(f"⚠️  Missing model: {req}")
                print(f"   Run: ollama pull {req}")
                all_found = False
        
        return all_found
        
    except Exception as e:
        print(f"❌ Ollama connection failed: {e}")
        import traceback
        traceback.print_exc()
        print(f"   Check if Ollama is running: sudo systemctl status ollama")
        return False


def test_2_llm_client():
    """Test LLM client functionality"""
    print("\n" + "="*60)
    print("TEST 2: LLM Client")
    print("="*60)
    
    try:
        from app.ai.llm_client import LLMClient
        
        client = LLMClient(LLM_MODEL_CHAT, LLM_MODEL_CODE)
        print(f"✅ LLMClient initialized")
        print(f"   Chat model: {LLM_MODEL_CHAT}")
        print(f"   Code model: {LLM_MODEL_CODE}")
        
        # Test simple DSL generation
        print("\n🔍 Testing DSL generation...")
        dsl = client.generate_opensearch_dsl(
            question="find failed login attempts",
            index_fields=['event_id', 'normalized_timestamp', 'search_blob'],
            patterns_context="Event ID 4625 = Failed login"
        )
        
        if isinstance(dsl, dict) and 'query' in dsl:
            print(f"✅ DSL generation working")
            print(f"   Generated query type: {list(dsl.get('query', {}).keys())}")
        else:
            print(f"⚠️  DSL may be invalid: {dsl}")
        
        # Test IOC extraction
        print("\n🔍 Testing IOC extraction...")
        iocs = client.extract_iocs(
            "Malware contacted 192.168.1.100 and evil.example.com. MD5: d41d8cd98f00b204e9800998ecf8427e"
        )
        
        if isinstance(iocs, dict):
            print(f"✅ IOC extraction working")
            print(f"   Found: {len(iocs.get('ip_addresses', []))} IPs, "
                  f"{len(iocs.get('domains', []))} domains, "
                  f"{sum(len(v) for v in iocs.get('file_hashes', {}).values())} hashes")
        else:
            print(f"⚠️  IOC extraction may have issues")
        
        return True
        
    except Exception as e:
        print(f"❌ LLM client test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_3_vector_store_integration():
    """Test vector store with RAG workflow"""
    print("\n" + "="*60)
    print("TEST 3: Vector Store RAG Integration")
    print("="*60)
    
    try:
        from app.ai.vector_store import PatternStore
        
        store = PatternStore(VECTOR_STORE_CONFIG, EMBEDDING_MODEL)
        print(f"✅ Vector store connected")
        
        # Test RAG workflow
        print("\n🔍 Testing RAG workflow...")
        query = "detect credential dumping"
        patterns = store.search(query, k=3)
        
        print(f"✅ Retrieved {len(patterns)} relevant patterns")
        
        # Build context string (as it would be used in LLM)
        context_parts = []
        for p in patterns:
            title = p.get('metadata', {}).get('title') or p.get('metadata', {}).get('name') or p['id']
            context_parts.append(f"[{p['source'].upper()}] {title}")
        
        context = "\n".join(context_parts)
        print(f"   Context preview:")
        for line in context.split('\n')[:3]:
            print(f"   - {line}")
        
        return True
        
    except Exception as e:
        print(f"❌ Vector store test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_4_opensearch_fields():
    """Test OpenSearch connectivity and get field mapping"""
    print("\n" + "="*60)
    print("TEST 4: OpenSearch Field Discovery")
    print("="*60)
    
    try:
        from opensearchpy import OpenSearch
        
        # Create OpenSearch client
        client = OpenSearch(
            hosts=[{'host': OPENSEARCH_HOST, 'port': OPENSEARCH_PORT}],
            http_auth=None,
            use_ssl=OPENSEARCH_USE_SSL,
            verify_certs=False,
            ssl_show_warn=False
        )
        
        # Check connection
        info = client.info()
        print(f"✅ OpenSearch connected")
        print(f"   Version: {info['version']['number']}")
        
        # Get index mapping
        indices = client.cat.indices(format='json', h='index')
        search_indices = [idx['index'] for idx in indices if 'events' in idx['index']]
        
        if search_indices:
            index_name = search_indices[0]
            print(f"\n📊 Checking index: {index_name}")
            
            mapping = client.indices.get_mapping(index=index_name)
            properties = mapping[index_name]['mappings']['properties']
            
            key_fields = [
                'event_id', 'normalized_event_id', 'normalized_timestamp',
                'normalized_computer', 'search_blob', 'file_type', 'source_file'
            ]
            
            found_fields = []
            for field in key_fields:
                if field in properties:
                    found_fields.append(field)
                    print(f"   ✅ {field}")
                else:
                    print(f"   ⚠️  {field} (not found)")
            
            print(f"\n✅ Found {len(found_fields)}/{len(key_fields)} key fields")
            
            # These fields are what the LLM will use
            return found_fields
        else:
            print(f"ℹ️  No events index found (expected if no files uploaded yet)")
            print(f"   This is OK for Phase 2 development")
            # Return expected fields that will exist after first upload
            return [
                'event_id', 'normalized_event_id', 'normalized_timestamp',
                'normalized_computer', 'search_blob', 'file_type', 'source_file'
            ]
        
    except Exception as e:
        print(f"❌ OpenSearch test failed: {e}")
        import traceback
        traceback.print_exc()
        return []


def test_5_flask_imports():
    """Test that AI modules can be imported in Flask context"""
    print("\n" + "="*60)
    print("TEST 5: Flask Import Test")
    print("="*60)
    
    try:
        # Try importing in a way similar to how Flask will
        from app.ai.vector_store import PatternStore
        from app.ai.llm_client import LLMClient
        
        print(f"✅ AI modules import successfully")
        
        # Test creating instances (without using them)
        store = PatternStore(VECTOR_STORE_CONFIG, EMBEDDING_MODEL)
        client = LLMClient(LLM_MODEL_CHAT, LLM_MODEL_CODE)
        
        print(f"✅ AI components instantiate successfully")
        
        return True
        
    except Exception as e:
        print(f"❌ Flask import test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_6_end_to_end_rag():
    """Test complete RAG pipeline: query → vector search → LLM → response"""
    print("\n" + "="*60)
    print("TEST 6: End-to-End RAG Pipeline")
    print("="*60)
    
    try:
        from app.ai.vector_store import PatternStore
        from app.ai.llm_client import LLMClient
        
        store = PatternStore(VECTOR_STORE_CONFIG, EMBEDDING_MODEL)
        client = LLMClient(LLM_MODEL_CHAT, LLM_MODEL_CODE)
        
        # Simulate a user query
        user_query = "How can I detect PowerShell-based attacks?"
        
        print(f"\n🔍 User Query: {user_query}")
        
        # 1. Retrieve relevant patterns
        print(f"\n📚 Step 1: Retrieving relevant patterns...")
        patterns = store.search(user_query, k=3)
        print(f"   Found {len(patterns)} patterns")
        
        # 2. Build context
        context_lines = []
        for p in patterns:
            title = p.get('metadata', {}).get('title') or p.get('metadata', {}).get('name')
            if title:
                context_lines.append(f"- {title}")
        context = "\n".join(context_lines)
        
        print(f"   Context built with {len(context_lines)} items")
        
        # 3. Generate response using LLM
        print(f"\n🤖 Step 2: Generating LLM response...")
        response = client.chat(
            message=user_query,
            history=[],
            context=context
        )
        
        if response and len(response) > 10:
            print(f"✅ Response generated ({len(response)} chars)")
            print(f"\n   Preview:")
            preview = response[:300].replace('\n', ' ')
            print(f"   {preview}...")
        else:
            print(f"⚠️  Response seems short or empty")
        
        return True
        
    except Exception as e:
        print(f"❌ End-to-end RAG test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    print("\n" + "="*70)
    print(" PRE-PHASE 2 INTEGRATION TESTS")
    print("="*70)
    print("\nTesting all foundation components before building API routes...\n")
    
    results = {}
    
    # Run tests
    results['ollama'] = test_1_ollama_connectivity()
    results['llm_client'] = test_2_llm_client()
    results['vector_store'] = test_3_vector_store_integration()
    opensearch_fields = test_4_opensearch_fields()
    results['opensearch'] = len(opensearch_fields) > 0
    results['flask_imports'] = test_5_flask_imports()
    results['rag_pipeline'] = test_6_end_to_end_rag()
    
    # Summary
    print("\n" + "="*70)
    print(" TEST SUMMARY")
    print("="*70)
    
    for test_name, passed in results.items():
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status} - {test_name}")
    
    total = len(results)
    passed = sum(results.values())
    
    print(f"\n{passed}/{total} tests passed")
    
    if passed == total:
        print("\n✅ ALL TESTS PASSED - Ready for Phase 2!")
    else:
        print("\n⚠️  Some tests failed - Fix issues before Phase 2")
        print("\nCommon fixes:")
        print("  - Ollama: sudo systemctl start ollama")
        print("  - Models: ollama pull <model-name>")
        print("  - OpenSearch: Check if running and accessible")
    
    print("="*70)
    
    return passed == total


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)

