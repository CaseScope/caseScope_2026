"""
Celery Task: Tag Noise Events
Tags events matching noise filter rules using parallel OpenSearch slice scrolling
"""

import os
import sys
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add app directory to Python path for imports
app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if app_dir not in sys.path:
    sys.path.insert(0, app_dir)

logger = logging.getLogger(__name__)

from celery_app import celery


@celery.task(bind=True)
def tag_noise_events(self, case_id, user_id, clear_previous=True):
    """
    Tag events matching noise filter rules using parallel processing
    
    Uses OpenSearch slice scrolling to process events in parallel across
    multiple threads. Number of slices determined by system configuration.
    
    Args:
        case_id: Case ID to process
        user_id: User initiating the task
        clear_previous: Whether to clear previous noise tags
    
    Returns:
        dict: Task results with statistics
    """
    # Import inside function to avoid circular imports
    from main import app, db
    from models import Case, NoiseFilterCategory, NoiseFilterRule
    from opensearchpy import OpenSearch, helpers
    from utils.noise_filter import _get_nested_field, _value_matches_pattern
    from utils.parallel_config import get_parallel_slice_count
    
    with app.app_context():
        try:
            # Get case
            case = Case.query.get(case_id)
            if not case:
                return {'state': 'FAILURE', 'error': 'Case not found'}
            
            # Get parallel processing config
            num_slices = get_parallel_slice_count()
            logger.info(f"Starting noise tagging for case {case_id} with {num_slices} parallel slices")
            
            # Get OpenSearch client
            os_client = OpenSearch(
                app.config.get('OPENSEARCH_HOSTS', ['http://localhost:9200']),
                http_auth=(
                    app.config.get('OPENSEARCH_USER', 'admin'),
                    app.config.get('OPENSEARCH_PASSWORD', 'admin')
                ),
                use_ssl=app.config.get('OPENSEARCH_USE_SSL', False),
                verify_certs=False,
                ssl_show_warn=False,
                timeout=30
            )
            
            index_name = f"case_{case_id}"
            
            # Get enabled rules
            enabled_cats = NoiseFilterCategory.query.filter_by(is_enabled=True).all()
            cat_ids = [c.id for c in enabled_cats]
            
            if not cat_ids:
                return {
                    'state': 'SUCCESS',
                    'events_scanned': 0,
                    'events_tagged': 0,
                    'total_matches': 0,
                    'rules_matched': 0,
                    'message': 'No enabled noise filter categories'
                }
            
            enabled_rules = NoiseFilterRule.query.filter(
                NoiseFilterRule.category_id.in_(cat_ids),
                NoiseFilterRule.is_enabled == True
            ).order_by(NoiseFilterRule.priority.asc()).all()
            
            if not enabled_rules:
                return {
                    'state': 'SUCCESS',
                    'events_scanned': 0,
                    'events_tagged': 0,
                    'total_matches': 0,
                    'rules_matched': 0,
                    'message': 'No enabled noise filter rules'
                }
            
            # Clear previous noise tags if requested
            if clear_previous:
                logger.info(f"Clearing previous noise tags for case {case_id}")
                # Use update_by_query to clear noise fields efficiently
                try:
                    os_client.update_by_query(
                        index=index_name,
                        body={
                            "script": {
                                "source": "ctx._source.remove('noise_matched'); ctx._source.remove('noise_rules'); ctx._source.remove('noise_categories')",
                                "lang": "painless"
                            },
                            "query": {
                                "exists": {"field": "noise_matched"}
                            }
                        },
                        wait_for_completion=True,
                        refresh=True
                    )
                except Exception as e:
                    logger.warning(f"Error clearing previous noise tags: {e}")
            
            # Count total events
            total_events = os_client.count(index=index_name, body={"query": {"match_all": {}}})['count']
            
            # Serialize rules for thread-safe passing (avoid DB queries in threads)
            rules_data = [{
                'name': r.name,
                'pattern': r.pattern,
                'filter_type': r.filter_type,
                'match_mode': r.match_mode,
                'is_case_sensitive': r.is_case_sensitive,
                'category_name': r.category.name,
                'priority': r.priority,
                'exclude_fields': r.exclude_fields  # Include exclusion list
            } for r in enabled_rules]
            
            logger.info(f"Prepared {len(rules_data)} rules for noise checking")
            
            def check_event_against_rules(event_data, rules):
                """
                Check event against rules without DB access (thread-safe).
                Rules must be pre-serialized dicts with all needed data.
                """
                matched_rules = []
                
                for rule in rules:
                    # Simple approach: Check search_blob first (contains everything)
                    search_blob = event_data.get('search_blob', '')
                    
                    if not search_blob:
                        continue  # Skip if no search_blob
                    
                    # Check if pattern matches in search_blob
                    if not _value_matches_pattern(search_blob, rule['pattern'], rule['match_mode'], rule['is_case_sensitive']):
                        continue  # Pattern doesn't match at all
                    
                    # Pattern matched! Now check if it's ONLY because of excluded field values
                    is_excluded_match = False
                    
                    if rule.get('exclude_fields'):
                        excluded_fields = [f.strip() for f in rule['exclude_fields'].split(',')]
                        
                        # Get values of excluded fields
                        excluded_values = []
                        for exc_field in excluded_fields:
                            exc_value = _get_nested_field(event_data, exc_field)
                            if exc_value:
                                excluded_values.append(str(exc_value))
                        
                        # Check if pattern matches ONLY in excluded field values
                        # If search_blob without excluded values still matches, it's real noise
                        search_blob_clean = search_blob
                        for exc_val in excluded_values:
                            search_blob_clean = search_blob_clean.replace(exc_val, '')
                        
                        # Re-check pattern against cleaned search_blob
                        if not _value_matches_pattern(search_blob_clean, rule['pattern'], rule['match_mode'], rule['is_case_sensitive']):
                            # Pattern only matched in excluded field values, skip this match
                            is_excluded_match = True
                    
                    if not is_excluded_match:
                        # Real noise match!
                        matched_rules.append({
                            'rule_name': rule['name'],
                            'category': rule['category_name'],
                            'pattern': rule['pattern'],
                            'filter_type': rule['filter_type'],
                            'matched_fields': ['search_blob'],
                            'priority': rule['priority']
                        })
                
                return {
                    'is_noise': len(matched_rules) > 0,
                    'matched_rules': matched_rules,
                    'total_matches': len(matched_rules)
                }
            
            # Shared progress tracking across threads
            progress_data = {
                'events_scanned': 0,
                'events_tagged': 0,
                'total_matches': 0,
                'rules_matched_detail': {},
                'lock': threading.Lock(),
                'last_progress_update': 0,
                'task_ref': self  # Store reference to task for progress updates
            }
            
            def process_slice(slice_id):
                """Process events for a specific slice"""
                slice_scanned = 0
                slice_tagged = 0
                slice_matches = 0
                slice_rules = {}
                
                try:
                    # Query with slice for parallel processing
                    query = {
                        "query": {"match_all": {}},
                        "size": 1000,
                        "slice": {
                            "id": slice_id,
                            "max": num_slices
                        }
                    }
                    
                    # Initialize scroll for this slice
                    result = os_client.search(index=index_name, body=query, scroll='5m')
                    scroll_id = result['_scroll_id']
                    hits = result['hits']['hits']
                    
                    while hits:
                        batch_updates = []
                        
                        for hit in hits:
                            slice_scanned += 1
                            event_data = hit['_source']
                            event_id = hit['_id']
                            
                            # Check against noise filters (using pre-loaded rules to avoid DB queries in threads)
                            noise_check = check_event_against_rules(event_data, rules_data)
                            
                            if noise_check['is_noise']:
                                slice_tagged += 1
                                slice_matches += noise_check['total_matches']
                                
                                # Track which rules matched
                                for rule in noise_check['matched_rules']:
                                    rule_name = rule['rule_name']
                                    if rule_name not in slice_rules:
                                        slice_rules[rule_name] = {
                                            'count': 0,
                                            'category': rule['category']
                                        }
                                    slice_rules[rule_name]['count'] += 1
                                
                                # Prepare update
                                batch_updates.append({
                                    '_op_type': 'update',
                                    '_index': index_name,
                                    '_id': event_id,
                                    'doc': {
                                        'noise_matched': True,
                                        'noise_rules': [r['rule_name'] for r in noise_check['matched_rules']],
                                        'noise_categories': list(set([r['category'] for r in noise_check['matched_rules']]))
                                    }
                                })
                            
                            # Update shared progress (thread-safe)
                            if slice_scanned % 50 == 0:
                                with progress_data['lock']:
                                    progress_data['events_scanned'] += 50
                                    progress_data['events_tagged'] += slice_tagged
                                    progress_data['total_matches'] += slice_matches
                                    
                                    # Merge slice rules into shared dict
                                    for rule_name, rule_info in slice_rules.items():
                                        if rule_name not in progress_data['rules_matched_detail']:
                                            progress_data['rules_matched_detail'][rule_name] = {
                                                'count': 0,
                                                'category': rule_info['category']
                                            }
                                        progress_data['rules_matched_detail'][rule_name]['count'] += rule_info['count']
                                    
                                    # Reset slice counters
                                    slice_tagged = 0
                                    slice_matches = 0
                                    slice_rules = {}
                                    
                                    # Note: Don't update Celery state from thread - causes task_id issues
                                    # Main thread will handle progress updates
                        
                        # Bulk update events in this batch
                        if batch_updates:
                            helpers.bulk(os_client, batch_updates)
                        
                        # Get next batch for this slice
                        result = os_client.scroll(scroll_id=scroll_id, scroll='5m')
                        scroll_id = result['_scroll_id']
                        hits = result['hits']['hits']
                    
                    # Clear scroll for this slice
                    os_client.clear_scroll(scroll_id=scroll_id)
                    
                    # Final update for remaining items
                    with progress_data['lock']:
                        progress_data['events_tagged'] += slice_tagged
                        progress_data['total_matches'] += slice_matches
                        for rule_name, rule_info in slice_rules.items():
                            if rule_name not in progress_data['rules_matched_detail']:
                                progress_data['rules_matched_detail'][rule_name] = {
                                    'count': 0,
                                    'category': rule_info['category']
                                }
                            progress_data['rules_matched_detail'][rule_name]['count'] += rule_info['count']
                    
                    logger.info(f"Slice {slice_id}/{num_slices} complete: {slice_scanned} events scanned")
                    return slice_scanned
                    
                except Exception as e:
                    logger.error(f"Error processing slice {slice_id}: {e}", exc_info=True)
                    raise
            
            # Process slices in parallel
            logger.info(f"Starting {num_slices} parallel threads...")
            with ThreadPoolExecutor(max_workers=num_slices) as executor:
                futures = [executor.submit(process_slice, i) for i in range(num_slices)]
                
                # Poll for progress while threads are running
                import time
                while any(not f.done() for f in futures):
                    time.sleep(2)  # Check every 2 seconds
                    
                    # Update Celery progress from main thread
                    with progress_data['lock']:
                        if progress_data['events_scanned'] > 0:
                            progress_pct = min(99, int((progress_data['events_scanned'] / total_events) * 100))
                            self.update_state(
                                state='PROGRESS',
                                meta={
                                    'progress': progress_pct,
                                    'status': f'Processing events: {progress_data["events_scanned"]}/{total_events}',
                                    'events_scanned': progress_data['events_scanned'],
                                    'total_events': total_events,
                                    'events_tagged': progress_data['events_tagged'],
                                    'rules_matched': len(progress_data['rules_matched_detail'])
                                }
                            )
                
                # Wait for all slices to complete and check for errors
                for future in futures:
                    try:
                        future.result()  # Raises exception if slice failed
                    except Exception as e:
                        logger.error(f"Slice processing failed: {e}")
                        # Cancel remaining slices
                        for f in futures:
                            f.cancel()
                        raise
            
            logger.info(
                f"Noise tagging complete for case {case_id}: "
                f"{progress_data['events_tagged']}/{progress_data['events_scanned']} events tagged "
                f"using {num_slices} parallel slices"
            )
            
            return {
                'state': 'SUCCESS',
                'progress': 100,
                'status': 'Complete',
                'events_scanned': progress_data['events_scanned'],
                'total_events': total_events,
                'events_tagged': progress_data['events_tagged'],
                'total_matches': progress_data['total_matches'],
                'rules_matched': len(progress_data['rules_matched_detail']),
                'rules_matched_detail': progress_data['rules_matched_detail'],
                'parallel_slices_used': num_slices
            }
            
        except Exception as e:
            logger.error(f"Error in noise tagging task: {e}", exc_info=True)
            return {
                'state': 'FAILURE',
                'error': str(e)
            }
