#!/usr/bin/env python3
"""
Check if AI components are available and can be enabled
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def check_ai_availability():
    """
    Check if all AI prerequisites are met
    Returns: (bool, list of issues)
    """
    issues = []
    
    # 1. Check Ollama
    try:
        import ollama
        try:
            ollama.list()
            print("✅ Ollama service running")
        except Exception as e:
            issues.append(f"Ollama not accessible: {e}")
            print(f"❌ Ollama not accessible: {e}")
    except ImportError:
        issues.append("ollama Python package not installed")
        print("❌ ollama Python package not installed")
    
    # 2. Check pgvector
    try:
        from app.config import VECTOR_STORE_CONFIG
        from app.ai.vector_store import PatternStore
        
        store = PatternStore(VECTOR_STORE_CONFIG, 'BAAI/bge-small-en-v1.5')
        stats = store.get_stats()
        
        if stats['total_patterns'] > 0:
            print(f"✅ Vector store ready ({stats['total_patterns']} patterns)")
        else:
            issues.append("Vector store empty (run scripts/ingest_patterns.py)")
            print("⚠️  Vector store empty (run scripts/ingest_patterns.py)")
    except Exception as e:
        issues.append(f"Vector store error: {e}")
        print(f"❌ Vector store error: {e}")
    
    # 3. Check FastEmbed
    try:
        from fastembed import TextEmbedding
        print("✅ FastEmbed available")
    except ImportError:
        issues.append("fastembed package not installed")
        print("❌ fastembed package not installed")
    
    # 4. Check models
    try:
        import ollama
        from app.config import LLM_MODEL_CHAT, LLM_MODEL_CODE
        
        response = ollama.list()
        model_names = []
        if hasattr(response, 'models'):
            model_names = [m.model for m in response.models]
        
        for model in [LLM_MODEL_CHAT, LLM_MODEL_CODE]:
            if any(model in name for name in model_names):
                print(f"✅ Model available: {model}")
            else:
                issues.append(f"Model not found: {model}")
                print(f"❌ Model not found: {model}")
    except Exception as e:
        issues.append(f"Cannot check models: {e}")
        print(f"⚠️  Cannot check models: {e}")
    
    return len(issues) == 0, issues


if __name__ == '__main__':
    print("="*60)
    print(" AI Component Availability Check")
    print("="*60)
    print()
    
    available, issues = check_ai_availability()
    
    print()
    print("="*60)
    if available:
        print("✅ AI can be ENABLED")
        print("   All components are ready")
        sys.exit(0)
    else:
        print("❌ AI should be DISABLED")
        print("   Issues found:")
        for issue in issues:
            print(f"   - {issue}")
        print()
        print("To enable AI:")
        print("  1. Run: ./scripts/setup_ai.sh")
        print("  2. Run: python3 scripts/ingest_patterns.py")
        print("  3. Set AI_ENABLED=True in config.py")
        sys.exit(1)

