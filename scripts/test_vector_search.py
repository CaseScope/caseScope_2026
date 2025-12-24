#!/usr/bin/env python3
"""
Test vector store search functionality
"""

import sys
import os

# Add app to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import VECTOR_STORE_CONFIG, EMBEDDING_MODEL
from app.ai.vector_store import PatternStore


def test_search():
    print("=== Testing Vector Store Search ===\n")
    
    store = PatternStore(VECTOR_STORE_CONFIG, EMBEDDING_MODEL)
    
    # Test queries
    test_queries = [
        "suspicious powershell execution",
        "lateral movement with psexec",
        "mimikatz credential dumping",
        "process injection techniques",
        "command and control beaconing"
    ]
    
    for query in test_queries:
        print(f"\n{'='*60}")
        print(f"Query: {query}")
        print('='*60)
        
        results = store.search(query, k=3)
        
        for i, result in enumerate(results, 1):
            print(f"\n{i}. [{result['source'].upper()}] {result['id']}")
            print(f"   Score: {result['score']:.4f}")
            
            # Extract title from metadata or content
            if result.get('metadata') and result['metadata'].get('title'):
                print(f"   Title: {result['metadata']['title']}")
            elif result.get('metadata') and result['metadata'].get('name'):
                print(f"   Name: {result['metadata']['name']}")
            
            # Show first 200 chars of content
            content_preview = result['content'][:200].replace('\n', ' ')
            print(f"   Preview: {content_preview}...")
    
    # Test source filtering
    print(f"\n\n{'='*60}")
    print("Testing source filter (Sigma only)")
    print('='*60)
    
    results = store.search("suspicious process creation", k=3, source_filter='sigma')
    
    for i, result in enumerate(results, 1):
        print(f"\n{i}. {result['id']} - Score: {result['score']:.4f}")
        if result.get('metadata') and result['metadata'].get('title'):
            print(f"   {result['metadata']['title']}")
    
    print("\n\n=== Test Complete ===")


if __name__ == '__main__':
    test_search()

