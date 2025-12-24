#!/usr/bin/env python3
"""
Ingest Sigma rules and MITRE ATT&CK into PostgreSQL + pgvector
"""

import sys
import os

# Add app to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import VECTOR_STORE_CONFIG, SIGMA_RULES_PATH, MITRE_ATTACK_PATH, EMBEDDING_MODEL
from app.ai.vector_store import PatternStore


def main():
    print("=== Pattern Ingestion (PostgreSQL + pgvector) ===")
    
    store = PatternStore(VECTOR_STORE_CONFIG, EMBEDDING_MODEL)
    
    # Check current count
    stats = store.get_stats()
    print(f"Current patterns in store: {stats['total_patterns']}")
    if stats.get('by_source'):
        for source, count in stats['by_source'].items():
            print(f"  - {source}: {count}")
    
    # Ingest Sigma rules
    print(f"\nIngesting Sigma rules from: {SIGMA_RULES_PATH}")
    sigma_count = store.add_sigma_rules(SIGMA_RULES_PATH)
    print(f"✓ Ingested {sigma_count} Sigma rules")
    
    # Ingest MITRE ATT&CK
    print(f"\nIngesting MITRE ATT&CK from: {MITRE_ATTACK_PATH}")
    mitre_count = store.add_mitre_attack(MITRE_ATTACK_PATH)
    print(f"✓ Ingested {mitre_count} MITRE techniques")
    
    # Final stats
    stats = store.get_stats()
    print(f"\n=== Complete ===")
    print(f"Total patterns in store: {stats['total_patterns']}")
    if stats.get('by_source'):
        for source, count in stats['by_source'].items():
            print(f"  - {source}: {count}")


if __name__ == '__main__':
    main()
