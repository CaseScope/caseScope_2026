#!/usr/bin/env python3
"""
Test AI toggle functionality
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_toggle():
    print("="*60)
    print(" AI Toggle Test")
    print("="*60)
    
    # Test 1: Check config setting
    print("\n1. Testing config flag...")
    from app.config import AI_ENABLED, AI_AUTO_DETECT
    print(f"   AI_ENABLED = {AI_ENABLED}")
    print(f"   AI_AUTO_DETECT = {AI_AUTO_DETECT}")
    
    # Test 2: Check availability
    print("\n2. Testing availability check...")
    from app.ai.ai_toggle import is_ai_available, is_ai_enabled
    
    enabled = is_ai_enabled()
    available, reason = is_ai_available()
    
    print(f"   Enabled: {enabled}")
    print(f"   Available: {available}")
    if not available:
        print(f"   Reason: {reason}")
    
    # Test 3: Get detailed status
    print("\n3. Getting detailed status...")
    from app.ai.ai_toggle import get_ai_status
    
    status = get_ai_status()
    print(f"   Status: {status['status']}")
    print(f"   Message: {status['message']}")
    print(f"   Components:")
    for name, state in status['components'].items():
        icon = "✅" if state else "❌"
        print(f"      {icon} {name}")
    
    # Test 4: Test decorator (simulate)
    print("\n4. Testing route protection...")
    
    if available:
        print("   ✅ AI routes would be accessible")
        print("   → /api/ai/query: 200 OK")
        print("   → /api/ai/analyze: 200 OK")
    else:
        print("   ❌ AI routes would return 404")
        print("   → /api/ai/query: 404 Not Found")
        print("   → /api/ai/analyze: 404 Not Found")
    
    # Summary
    print("\n" + "="*60)
    print(" Summary")
    print("="*60)
    
    if AI_ENABLED and available:
        print("✅ AI ACTIVE: All features operational")
    elif AI_ENABLED and not available:
        print("⚠️  AI ENABLED but UNAVAILABLE")
        print(f"   Reason: {reason}")
        print("   Routes will return 404 until fixed")
    else:
        print("ℹ️  AI DISABLED in configuration")
        print("   To enable: Set AI_ENABLED=True in config.py")
    
    print()


if __name__ == '__main__':
    test_toggle()

