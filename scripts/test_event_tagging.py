#!/usr/bin/env python3
"""
Test Event Tagging System
Tests the analyst event tagging functionality
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from opensearchpy import OpenSearch
from app.config import Config
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def test_event_tagging():
    """Test event tagging functionality"""
    
    print("\n" + "="*60)
    print("Event Tagging System Test")
    print("="*60 + "\n")
    
    # Connect to OpenSearch
    client = OpenSearch(
        hosts=[{'host': Config.OPENSEARCH_HOST, 'port': Config.OPENSEARCH_PORT}],
        use_ssl=Config.OPENSEARCH_USE_SSL,
        verify_certs=False,
        ssl_show_warn=False,
        timeout=30
    )
    
    # Get list of case indices
    indices = client.indices.get_alias(index="case_*")
    
    if not indices:
        print("❌ No case indices found")
        return False
    
    print(f"✓ Found {len(indices)} case index(es)")
    
    # Test with first case index
    test_index = list(indices.keys())[0]
    print(f"\n📊 Testing with index: {test_index}")
    
    # 1. Check if index has analyst_tagged field in mapping
    print("\n1. Checking index mapping...")
    mapping = client.indices.get_mapping(index=test_index)
    properties = mapping[test_index]['mappings'].get('properties', {})
    
    if 'analyst_tagged' in properties:
        print("   ✓ analyst_tagged field exists in mapping")
        print(f"   Type: {properties['analyst_tagged']['type']}")
    else:
        print("   ⚠ analyst_tagged field not in mapping (will be added dynamically)")
    
    # 2. Count total events
    print("\n2. Counting events...")
    total_count = client.count(index=test_index)['count']
    print(f"   ✓ Total events: {total_count:,}")
    
    if total_count == 0:
        print("   ⚠ No events found - cannot test tagging")
        return True
    
    # 3. Get a sample event
    print("\n3. Getting sample event...")
    sample_query = {
        'size': 1,
        'query': {'match_all': {}}
    }
    
    sample_result = client.search(index=test_index, body=sample_query)
    
    if not sample_result['hits']['hits']:
        print("   ❌ Could not retrieve sample event")
        return False
    
    sample_event = sample_result['hits']['hits'][0]
    event_id = sample_event['_id']
    print(f"   ✓ Sample event ID: {event_id}")
    
    # 4. Check current tag status
    print("\n4. Checking current tag status...")
    current_tag = sample_event['_source'].get('analyst_tagged', False)
    print(f"   Current status: {'Tagged' if current_tag else 'Not tagged'}")
    
    # 5. Simulate tagging (update document)
    print("\n5. Simulating tag operation...")
    from datetime import datetime, timezone
    
    try:
        update_body = {
            'doc': {
                'analyst_tagged': True,
                'analyst_tagged_by': 'test_script',
                'analyst_tagged_at': datetime.now(timezone.utc).isoformat()
            }
        }
        
        client.update(index=test_index, id=event_id, body=update_body)
        print("   ✓ Successfully tagged event")
        
        # Refresh index
        client.indices.refresh(index=test_index)
        
        # Verify tag
        updated_event = client.get(index=test_index, id=event_id)
        is_tagged = updated_event['_source'].get('analyst_tagged', False)
        
        if is_tagged:
            print("   ✓ Tag verified in OpenSearch")
            tagged_by = updated_event['_source'].get('analyst_tagged_by')
            tagged_at = updated_event['_source'].get('analyst_tagged_at')
            print(f"     Tagged by: {tagged_by}")
            print(f"     Tagged at: {tagged_at}")
        else:
            print("   ❌ Tag not found after update")
            return False
            
    except Exception as e:
        print(f"   ❌ Error tagging event: {e}")
        return False
    
    # 6. Test query for tagged events
    print("\n6. Testing tagged events query...")
    tagged_query = {
        'query': {
            'term': {'analyst_tagged': True}
        }
    }
    
    try:
        tagged_count = client.count(index=test_index, body=tagged_query)['count']
        print(f"   ✓ Found {tagged_count} tagged event(s)")
        
        if tagged_count < 1:
            print("   ⚠ Warning: Expected at least 1 tagged event")
            
    except Exception as e:
        print(f"   ❌ Error querying tagged events: {e}")
        return False
    
    # 7. Test untag operation
    print("\n7. Testing untag operation...")
    try:
        untag_body = {
            'doc': {
                'analyst_tagged': False,
                'analyst_tagged_by': None,
                'analyst_tagged_at': None
            }
        }
        
        client.update(index=test_index, id=event_id, body=untag_body)
        print("   ✓ Successfully untagged event")
        
        # Refresh and verify
        client.indices.refresh(index=test_index)
        untagged_event = client.get(index=test_index, id=event_id)
        is_tagged = untagged_event['_source'].get('analyst_tagged', False)
        
        if not is_tagged:
            print("   ✓ Untag verified in OpenSearch")
        else:
            print("   ❌ Event still appears tagged after untag")
            return False
            
    except Exception as e:
        print(f"   ❌ Error untagging event: {e}")
        return False
    
    # 8. API endpoint test info
    print("\n8. API Endpoints Available:")
    print("   POST /search/api/event/<event_id>/tag")
    print("   POST /search/api/event/<event_id>/untag")
    print("   GET  /search/api/tagged_events/count")
    print("   GET  /search/api/tagged_events")
    print("   GET  /search/api/events?tagged_only=true")
    
    print("\n" + "="*60)
    print("✓ All tests passed!")
    print("="*60 + "\n")
    
    return True


if __name__ == '__main__':
    try:
        success = test_event_tagging()
        sys.exit(0 if success else 1)
    except Exception as e:
        logger.error(f"Test failed with exception: {e}", exc_info=True)
        sys.exit(1)

