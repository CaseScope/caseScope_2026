#!/usr/bin/env python3
"""
Fix OpenSearch Index Field Limits
Updates all case indexes to support 50,000 fields instead of default 5000
"""

import sys
import os
sys.path.insert(0, '/opt/casescope')

from opensearchpy import OpenSearch
from app.config import (
    OPENSEARCH_HOST, OPENSEARCH_PORT, OPENSEARCH_USE_SSL,
    OPENSEARCH_TOTAL_FIELDS_LIMIT, OPENSEARCH_NESTED_FIELDS_LIMIT
)

def fix_all_indexes():
    """Update field limits on all case_* indexes"""
    
    # Connect to OpenSearch
    client = OpenSearch(
        hosts=[{'host': OPENSEARCH_HOST, 'port': OPENSEARCH_PORT}],
        use_ssl=OPENSEARCH_USE_SSL,
        verify_certs=False,
        ssl_show_warn=False,
        timeout=30
    )
    
    # Get all indexes
    all_indexes = client.indices.get_alias(index="*")
    case_indexes = [idx for idx in all_indexes.keys() if idx.startswith('case_')]
    
    print(f"Found {len(case_indexes)} case indexes")
    print(f"Will update field limits to:")
    print(f"  - mapping.total_fields.limit: {OPENSEARCH_TOTAL_FIELDS_LIMIT}")
    print(f"  - mapping.nested_fields.limit: {OPENSEARCH_NESTED_FIELDS_LIMIT}")
    print()
    
    updated = 0
    failed = 0
    
    for index_name in case_indexes:
        try:
            # Update index settings
            settings = {
                'index': {
                    'mapping.total_fields.limit': OPENSEARCH_TOTAL_FIELDS_LIMIT,
                    'mapping.nested_fields.limit': OPENSEARCH_NESTED_FIELDS_LIMIT
                }
            }
            
            client.indices.put_settings(index=index_name, body=settings)
            print(f"✓ Updated {index_name}")
            updated += 1
            
        except Exception as e:
            print(f"✗ Failed to update {index_name}: {e}")
            failed += 1
    
    print()
    print(f"Summary: {updated} updated, {failed} failed")
    
    return updated, failed

if __name__ == '__main__':
    print("=" * 70)
    print("Fix OpenSearch Index Field Limits")
    print("=" * 70)
    print()
    
    updated, failed = fix_all_indexes()
    
    if failed > 0:
        sys.exit(1)
    else:
        print()
        print("All indexes updated successfully!")
        sys.exit(0)


