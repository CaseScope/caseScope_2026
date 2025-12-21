"""
EVTX Event Description Enrichment
Provides functions to update event descriptions in OpenSearch without full reindex
Similar to IOC rehunting pattern - modular and reusable
"""
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


def update_event_descriptions_for_case(opensearch_client, db, EventDescription, case_id: int) -> Dict:
    """
    Update event_title, event_description, event_category fields in OpenSearch
    for all events in a case WITHOUT full reindex.
    
    Uses OpenSearch update_by_query API with painless script to update fields
    based on current EventDescription database.
    
    Args:
        opensearch_client: OpenSearch client instance
        db: SQLAlchemy database session
        EventDescription: EventDescription model class
        case_id: Case ID to update events for
        
    Returns:
        Dict with stats: {
            'status': 'success'|'error',
            'events_updated': int,
            'descriptions_applied': int,
            'message': str
        }
    """
    try:
        index_name = f"case_{case_id}"
        
        # Check if index exists
        if not opensearch_client.indices.exists(index=index_name):
            return {
                'status': 'error',
                'events_updated': 0,
                'descriptions_applied': 0,
                'message': f'Index {index_name} does not exist'
            }
        
        # Get all event descriptions from database
        descriptions = db.session.query(EventDescription).all()
        
        if not descriptions:
            return {
                'status': 'success',
                'events_updated': 0,
                'descriptions_applied': 0,
                'message': 'No event descriptions in database'
            }
        
        # Build a map of event_id -> description data
        # Key: "event_id|event_source" for matching
        desc_map = {}
        for desc in descriptions:
            key = f"{desc.event_id}|{desc.event_source or 'Security'}"
            desc_map[key] = {
                'title': desc.title,
                'description': desc.description,
                'category': desc.category
            }
        
        logger.info(f"[EVTX ENRICHMENT] Loaded {len(descriptions)} event descriptions from database")
        
        # Update events in batches by Event ID
        # This is more efficient than updating all events at once
        updated_count = 0
        descriptions_applied = 0
        
        for desc in descriptions:
            try:
                # Build update query for this specific Event ID
                # We'll use update_by_query with a script
                query = {
                    "bool": {
                        "must": [
                            {"term": {"Event.System.EventID": desc.event_id}}
                        ]
                    }
                }
                
                # Add event_source filter if available
                # Check nested structure for Channel field
                if desc.event_source and desc.event_source != 'Security':
                    query["bool"]["should"] = [
                        {"match": {"Event.System.Channel": desc.event_source}},
                        {"match": {"Event.System.Provider.Name": desc.event_source}}
                    ]
                    query["bool"]["minimum_should_match"] = 1
                
                # Painless script to update description fields
                script = {
                    "source": """
                        ctx._source.event_title = params.title;
                        ctx._source.event_description = params.description;
                        ctx._source.event_category = params.category;
                    """,
                    "params": {
                        "title": desc.title,
                        "description": desc.description,
                        "category": desc.category
                    },
                    "lang": "painless"
                }
                
                # Execute update_by_query
                response = opensearch_client.update_by_query(
                    index=index_name,
                    body={
                        "query": query,
                        "script": script
                    },
                    conflicts='proceed',  # Continue on version conflicts
                    wait_for_completion=True,  # Wait for operation to complete
                    refresh=True  # Refresh index after update
                )
                
                events_updated_for_this_id = response.get('updated', 0)
                updated_count += events_updated_for_this_id
                
                if events_updated_for_this_id > 0:
                    descriptions_applied += 1
                    logger.debug(f"[EVTX ENRICHMENT] Updated {events_updated_for_this_id} events for Event ID {desc.event_id}")
                
            except Exception as e:
                logger.warning(f"[EVTX ENRICHMENT] Failed to update Event ID {desc.event_id}: {e}")
                continue
        
        logger.info(f"[EVTX ENRICHMENT] ✓ Updated {updated_count} events in case {case_id} ({descriptions_applied} descriptions applied)")
        
        return {
            'status': 'success',
            'events_updated': updated_count,
            'descriptions_applied': descriptions_applied,
            'message': f'Updated {updated_count} events with {descriptions_applied} descriptions'
        }
        
    except Exception as e:
        logger.error(f"[EVTX ENRICHMENT] Error updating case {case_id}: {e}", exc_info=True)
        return {
            'status': 'error',
            'events_updated': 0,
            'descriptions_applied': 0,
            'message': str(e)
        }


def update_event_descriptions_global(opensearch_client, db, EventDescription, Case) -> Dict:
    """
    Update event descriptions for ALL cases.
    
    Args:
        opensearch_client: OpenSearch client instance
        db: SQLAlchemy database session
        EventDescription: EventDescription model class
        Case: Case model class
        
    Returns:
        Dict with stats: {
            'status': 'success'|'error',
            'cases_processed': int,
            'total_events_updated': int,
            'total_descriptions_applied': int,
            'message': str
        }
    """
    try:
        # Get all cases
        cases = db.session.query(Case).all()
        
        if not cases:
            return {
                'status': 'success',
                'cases_processed': 0,
                'total_events_updated': 0,
                'total_descriptions_applied': 0,
                'message': 'No cases found'
            }
        
        total_events_updated = 0
        total_descriptions_applied = 0
        cases_processed = 0
        
        logger.info(f"[EVTX ENRICHMENT GLOBAL] Starting global update for {len(cases)} cases")
        
        for case in cases:
            result = update_event_descriptions_for_case(
                opensearch_client, db, EventDescription, case.id
            )
            
            if result['status'] == 'success':
                total_events_updated += result['events_updated']
                total_descriptions_applied += result['descriptions_applied']
                cases_processed += 1
        
        logger.info(f"[EVTX ENRICHMENT GLOBAL] ✓ Processed {cases_processed} cases, updated {total_events_updated} events")
        
        return {
            'status': 'success',
            'cases_processed': cases_processed,
            'total_events_updated': total_events_updated,
            'total_descriptions_applied': total_descriptions_applied,
            'message': f'Processed {cases_processed} cases, updated {total_events_updated} events'
        }
        
    except Exception as e:
        logger.error(f"[EVTX ENRICHMENT GLOBAL] Error: {e}", exc_info=True)
        return {
            'status': 'error',
            'cases_processed': 0,
            'total_events_updated': 0,
            'total_descriptions_applied': 0,
            'message': str(e)
        }

