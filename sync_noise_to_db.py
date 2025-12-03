#!/usr/bin/env python3
"""
One-time script to sync noise events from OpenSearch to Database
Fixes the missing EventStatus records from reindex with buggy code
"""

import sys
sys.path.insert(0, '/opt/casescope')

from opensearchpy import OpenSearch
from opensearchpy.helpers import scan
from event_status import bulk_set_status, STATUS_NOISE
from models import db
from main import app

def sync_noise_events_to_db(case_id: int):
    """Query OpenSearch for all noise events and sync to database"""
    
    client = OpenSearch(
        hosts=[{'host': 'localhost', 'port': 9200}],
        http_compress=True,
        timeout=60
    )
    
    index_name = f"case_{case_id}"
    
    print("="*70)
    print(f"Syncing noise events from OpenSearch to Database (Case {case_id})")
    print("="*70)
    
    # Query all events with event_status='noise'
    query = {
        "query": {
            "term": {"event_status": "noise"}
        },
        "_source": False  # We only need the _id
    }
    
    print("Scanning OpenSearch for noise events...")
    noise_event_ids = []
    
    try:
        for hit in scan(client, index=index_name, query=query, scroll='5m'):
            noise_event_ids.append(hit['_id'])
            
            if len(noise_event_ids) % 10000 == 0:
                print(f"  Found {len(noise_event_ids):,} noise events so far...")
        
        print(f"\n✓ Found {len(noise_event_ids):,} total noise events in OpenSearch")
        
        if not noise_event_ids:
            print("No noise events to sync")
            return
        
        # Sync to database using batched bulk_set_status
        print(f"\nSyncing {len(noise_event_ids):,} events to database...")
        with app.app_context():
            result = bulk_set_status(
                case_id=case_id,
                event_ids=noise_event_ids,
                status=STATUS_NOISE,
                user_id=None,
                notes="Backfill sync from OpenSearch"
            )
            
            print(f"\n✓ Database sync complete!")
            print(f"  - Updated: {result.get('updated', 0):,}")
            print(f"  - Created: {result.get('created', 0):,}")
            
            if 'error' in result:
                print(f"  ⚠️ Error: {result['error']}")
        
        print("="*70)
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    case_id = int(sys.argv[1]) if len(sys.argv) > 1 else 15
    sync_noise_events_to_db(case_id)

