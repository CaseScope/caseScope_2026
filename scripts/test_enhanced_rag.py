#!/usr/bin/env python3
"""
Test Enhanced RAG System - Before vs After Tier 1 Ingestion
Shows how the new patterns improve hunting query quality
"""

import sys
import os

# Add app to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import VECTOR_STORE_CONFIG, EMBEDDING_MODEL
from app.ai.vector_store import PatternStore


def test_query(store: PatternStore, query: str, k: int = 10):
    """Test a query and show what patterns are retrieved"""
    print("\n" + "="*80)
    print(f"QUERY: {query}")
    print("="*80)
    
    results = store.search(query, k=k)
    
    if not results:
        print("  ⚠ No results found")
        return
    
    # Group by source
    by_source = {}
    for r in results:
        source = r['source']
        if source not in by_source:
            by_source[source] = []
        by_source[source].append(r)
    
    # Display results grouped by source
    for source in sorted(by_source.keys()):
        patterns = by_source[source]
        print(f"\n{source.upper()} ({len(patterns)} patterns):")
        print("-" * 80)
        
        for i, pattern in enumerate(patterns, 1):
            # Extract key info from metadata
            metadata = pattern.get('metadata', {})
            title = metadata.get('title', metadata.get('name', pattern['id']))
            score = pattern.get('score', 0)
            
            print(f"\n  {i}. {title}")
            print(f"     ID: {pattern['id']}")
            print(f"     Similarity: {score:.3f}")
            
            # Show technique IDs if available
            if 'technique_id' in metadata:
                print(f"     Technique: {metadata['technique_id']}")
            elif 'techniques' in metadata and metadata['techniques']:
                print(f"     Techniques: {', '.join(metadata['techniques'][:3])}")
            
            # Show type for new sources
            if 'type' in metadata:
                print(f"     Type: {metadata['type']}")
            
            # Show first 200 chars of content
            content_preview = pattern['content'][:200].replace('\n', ' ')
            print(f"     Preview: {content_preview}...")


def main():
    """Run test queries"""
    print("="*80)
    print("ENHANCED RAG TESTING - TIER 1 PATTERNS")
    print("="*80)
    
    # Initialize store
    store = PatternStore(VECTOR_STORE_CONFIG, EMBEDDING_MODEL)
    
    # Get stats
    stats = store.get_stats()
    print(f"\nCurrent Pattern Count: {stats['total_patterns']}")
    print("\nBreakdown by Source:")
    for source, count in sorted(stats['by_source'].items()):
        print(f"  - {source}: {count}")
    
    # Test queries representing common hunting scenarios
    test_queries = [
        "Do you see signs of brute force attempts?",
        "Is there evidence of pass the hash attacks?",
        "Find lateral movement activity",
        "Detect credential dumping",
        "Look for Kerberos brute force",
        "Find PowerShell obfuscation",
        "Detect privilege escalation"
    ]
    
    print("\n" + "="*80)
    print("TESTING HUNTING QUERIES")
    print("="*80)
    
    for query in test_queries:
        test_query(store, query, k=10)
    
    # Summary
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)
    print("\nTier 1 patterns provide:")
    print("  ✓ Analytics with detection thresholds (MITRE CAR)")
    print("  ✓ Step-by-step hunting procedures (Threat Hunter Playbook)")
    print("  ✓ Adversary emulation examples (Atomic Red Team)")
    print("\nThese enhance the LLM's ability to:")
    print("  • Generate more specific queries")
    print("  • Apply proper thresholds (e.g., >10 failures in 5 minutes)")
    print("  • Correlate multiple event types")
    print("  • Reference real-world attack patterns")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠ Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n✗ Test error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

