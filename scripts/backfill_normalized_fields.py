#!/usr/bin/env python3
"""
Backfill Normalized Fields for All Events
Updates existing OpenSearch documents to add normalized_timestamp, normalized_computer, and normalized_event_id
Supports EVTX, CSV, NDJSON, and all other file types
"""

import sys
import os
sys.path.insert(0, '/opt/casescope')

from opensearchpy import OpenSearch
from opensearchpy.helpers import scan, bulk
from app.utils.event_normalization import normalize_event
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def get_opensearch_client():
    """Get OpenSearch client"""
    from app.config import Config
    return OpenSearch(
        hosts=[{'host': Config.OPENSEARCH_HOST, 'port': Config.OPENSEARCH_PORT}],
        use_ssl=Config.OPENSEARCH_USE_SSL,
        verify_certs=False,
        ssl_show_warn=False,
        timeout=60
    )


def backfill_case(client, case_id):
    """
    Backfill normalized fields for a specific case
    
    Args:
        client: OpenSearch client
        case_id: Case ID to process
    """
    index_name = f"case_{case_id}"
    
    # Check if index exists
    if not client.indices.exists(index=index_name):
        logger.warning(f"Index {index_name} does not exist, skipping")
        return
    
    logger.info(f"Processing case {case_id} (index: {index_name})")
    
    # Query for documents missing any normalized field (OR condition)
    # This catches events that might have some but not all normalized fields
    query = {
        "query": {
            "bool": {
                "should": [
                    {"bool": {"must_not": {"exists": {"field": "normalized_timestamp"}}}},
                    {"bool": {"must_not": {"exists": {"field": "normalized_computer"}}}},
                    {"bool": {"must_not": {"exists": {"field": "normalized_event_id"}}}}
                ],
                "minimum_should_match": 1
            }
        }
    }
    
    # Scan all matching documents
    total_docs = 0
    update_actions = []
    
    for doc in scan(client, index=index_name, query=query, size=1000):
        doc_id = doc['_id']
        source = doc['_source'].copy()  # Make a copy to avoid modifying original
        
        # Use comprehensive normalization function (handles all file types)
        normalized = normalize_event(source)
        
        # Build update document with normalized fields
        update_doc = {}
        
        if 'normalized_timestamp' in normalized:
            update_doc['normalized_timestamp'] = normalized['normalized_timestamp']
        
        if 'normalized_computer' in normalized:
            update_doc['normalized_computer'] = normalized['normalized_computer']
        
        if 'normalized_event_id' in normalized:
            update_doc['normalized_event_id'] = normalized['normalized_event_id']
        
        # Only update if we have something to update
        if update_doc:
            update_actions.append({
                '_op_type': 'update',
                '_index': index_name,
                '_id': doc_id,
                'doc': update_doc
            })
            total_docs += 1
        
        # Bulk update every 500 documents
        if len(update_actions) >= 500:
            logger.info(f"Updating batch of {len(update_actions)} documents...")
            success, failed = bulk(client, update_actions, raise_on_error=False)
            logger.info(f"Batch complete: {success} succeeded, {len(failed)} failed")
            update_actions = []
    
    # Update remaining documents
    if update_actions:
        logger.info(f"Updating final batch of {len(update_actions)} documents...")
        success, failed = bulk(client, update_actions, raise_on_error=False)
        logger.info(f"Final batch complete: {success} succeeded, {len(failed)} failed")
    
    logger.info(f"Case {case_id} complete: {total_docs} documents processed")
    return total_docs


def main():
    """Main function"""
    logger.info("Starting normalized fields backfill")
    
    # Get list of case indices
    client = get_opensearch_client()
    
    # Get all indices matching case_* pattern
    indices = client.indices.get(index="case_*")
    
    total_cases = 0
    total_docs = 0
    
    for index_name in sorted(indices.keys()):
        # Extract case ID from index name
        case_id = index_name.replace('case_', '')
        
        try:
            docs_updated = backfill_case(client, case_id)
            total_cases += 1
            total_docs += docs_updated
        except Exception as e:
            logger.error(f"Error processing case {case_id}: {e}")
            continue
    
    logger.info(f"Backfill complete!")
    logger.info(f"Cases processed: {total_cases}")
    logger.info(f"Documents updated: {total_docs}")


if __name__ == '__main__':
    main()

