"""
Search Routes
Event search with boolean operators and efficient deep pagination using search_after
"""

from flask import Blueprint, render_template, jsonify, request, session
from flask_login import login_required, current_user
from opensearchpy import OpenSearch
from opensearchpy.exceptions import NotFoundError
import logging

logger = logging.getLogger(__name__)

search_bp = Blueprint('search', __name__, url_prefix='/search')


def get_opensearch_client():
    """Get OpenSearch client"""
    from app.config import Config
    return OpenSearch(
        hosts=[{'host': Config.OPENSEARCH_HOST, 'port': Config.OPENSEARCH_PORT}],
        use_ssl=Config.OPENSEARCH_USE_SSL,
        verify_certs=False,
        ssl_show_warn=False,
        timeout=30
    )


@search_bp.route('/')
@search_bp.route('/events')
@login_required
def events():
    """
    Main event search page
    """
    # Get selected case from session
    case_id = session.get('selected_case_id')
    
    if not case_id:
        return render_template('search/events.html', 
                             case_id=None,
                             error='No case selected. Please select a case first.')
    
    # Verify user has access to this case
    from models import Case
    case = Case.query.get(case_id)
    
    if not case:
        return render_template('search/events.html',
                             case_id=None,
                             error='Case not found.')
    
    # Check permissions
    if current_user.role == 'read-only':
        if case.id != current_user.case_assigned:
            return render_template('search/events.html',
                                 case_id=None,
                                 error='Access denied to this case.')
    
    return render_template('search/events.html',
                         case=case,
                         case_id=case_id)


@search_bp.route('/api/events')
@login_required
def api_search_events():
    """
    API endpoint for event search with efficient deep pagination
    
    Uses search_after for stateless pagination (bypasses 10K limit).
    For pages near the end, searches in reverse for better performance.
    
    Query Parameters:
    - q: Search query (supports boolean operators)
    - page: Page number (default: 1)
    - per_page: Results per page (default: 50, max: 100)
    - sort: Sort field (default: normalized_timestamp)
    - order: Sort order (asc/desc, default: desc)
    """
    try:
        # Get case ID from session
        case_id = session.get('selected_case_id')
        if not case_id:
            return jsonify({'error': 'No case selected'}), 400
        
        # Verify access
        from models import Case
        case = Case.query.get(case_id)
        if not case:
            return jsonify({'error': 'Case not found'}), 404
        
        if current_user.role == 'read-only':
            if case.id != current_user.case_assigned:
                return jsonify({'error': 'Access denied'}), 403
        
        # Get query parameters
        query_string = request.args.get('q', '').strip()
        page = max(1, int(request.args.get('page', 1)))
        per_page = min(100, max(1, int(request.args.get('per_page', 50))))
        sort_field = request.args.get('sort', 'normalized_timestamp')  # Using normalized field for consistency across log types
        sort_order = request.args.get('order', 'desc')
        
        # Get file type filters
        file_types_param = request.args.get('file_types', '')
        file_type_filters = [ft.strip().upper() for ft in file_types_param.split(',') if ft.strip()]
        
        # Get event tag filters (works like file types - checked = include those events)
        event_tags_param = request.args.get('event_tags', '')
        event_tag_filters = [tag.strip().lower() for tag in event_tags_param.split(',') if tag.strip()]
        
        # Get noise category filters (checked = show those noise categories)
        noise_categories_param = request.args.get('noise_categories', '')
        noise_category_filters = [cat.strip() for cat in noise_categories_param.split(',') if cat.strip()]
        
        logger.info(f"Search request - query: '{query_string}', file_types: {file_type_filters}, event_tags: {event_tag_filters}, noise_categories: {noise_category_filters}")
        
        # Build OpenSearch query
        index_name = f"case_{case_id}"
        client = get_opensearch_client()
        
        # Check if index exists
        if not client.indices.exists(index=index_name):
            return jsonify({
                'events': [],
                'total': 0,
                'page': page,
                'per_page': per_page,
                'total_pages': 0
            })
        
        # Build base query
        must_clauses = []
        
        # Add search query if provided
        if query_string:
            must_clauses.append({
                'query_string': {
                    'query': query_string,
                    'fields': ['search_blob'],
                    'default_operator': 'AND',
                    'lenient': True
                }
            })
        
        # Add file type filter if provided
        if file_type_filters:
            # Build a should clause that matches either file_type field or source_file extension
            file_type_clauses = []
            
            for ft in file_type_filters:
                # Match on file_type field (for newly indexed data)
                file_type_clauses.append({
                    'term': {'file_type.keyword': ft}
                })
                
                # Match on source_file extension (for existing data without file_type field)
                if ft == 'EVTX':
                    file_type_clauses.append({
                        'wildcard': {'source_file': '*.evtx'}
                    })
                elif ft == 'NDJSON':
                    file_type_clauses.append({
                        'bool': {
                            'should': [
                                {'wildcard': {'source_file': '*.ndjson'}},
                                {'wildcard': {'source_file': '*.json'}},
                                {'wildcard': {'source_file': '*.jsonl'}}
                            ]
                        }
                    })
                elif ft == 'CSV':
                    file_type_clauses.append({
                        'wildcard': {'source_file': '*.csv'}
                    })
                elif ft == 'IIS':
                    file_type_clauses.append({
                        'wildcard': {'source_file': '*.log'}
                    })
            
            must_clauses.append({
                'bool': {
                    'should': file_type_clauses,
                    'minimum_should_match': 1
                }
            })
        
        # Add event tag filters
        # Logic: If all tags are checked, show ALL events (no filter)
        #        If some tags unchecked, exclude those types
        # Tag types: 'other' (no tag, no IOC, no Sigma), 'tagged' (analyst tagged), 'ioc' (has IOC hits), 'sigma' (has Sigma hits)
        
        # Only apply filter if not all tags are selected
        all_tag_types = ['other', 'tagged', 'ioc', 'sigma']
        if event_tag_filters and set(event_tag_filters) != set(all_tag_types):
            # Some tags are unchecked, so we need to filter them out
            tag_must_not_clauses = []
            
            # Get IOC event IDs (we'll need this for multiple filters)
            from models import EventIOCHit, EventSigmaHit
            from main import db
            
            ioc_hits_query = db.session.query(
                EventIOCHit.opensearch_doc_id
            ).filter(
                EventIOCHit.case_id == case_id
            ).distinct()
            
            ioc_event_ids = [hit[0] for hit in ioc_hits_query.all()]
            logger.info(f"Found {len(ioc_event_ids)} events with IOC hits")
            
            # Get Sigma event IDs
            sigma_hits_query = db.session.query(
                EventSigmaHit.opensearch_doc_id
            ).filter(
                EventSigmaHit.case_id == case_id
            ).distinct()
            
            sigma_event_ids = [hit[0] for hit in sigma_hits_query.all()]
            logger.info(f"Found {len(sigma_event_ids)} events with Sigma hits")
            
            # If 'other' not checked, exclude events with no tags, no IOCs, and no Sigma
            if 'other' not in event_tag_filters:
                # Exclude events that are NOT tagged AND NOT in IOC list AND NOT in Sigma list
                exclude_conditions = [
                    {'term': {'analyst_tagged': True}}
                ]
                if ioc_event_ids:
                    exclude_conditions.append({'ids': {'values': ioc_event_ids}})
                if sigma_event_ids:
                    exclude_conditions.append({'ids': {'values': sigma_event_ids}})
                
                tag_must_not_clauses.append({
                    'bool': {
                        'must_not': exclude_conditions
                    }
                })
            
            # If 'tagged' not checked, exclude tagged events
            if 'tagged' not in event_tag_filters:
                tag_must_not_clauses.append({
                    'term': {'analyst_tagged': True}
                })
            
            # If 'ioc' not checked, exclude IOC events
            if 'ioc' not in event_tag_filters and ioc_event_ids:
                tag_must_not_clauses.append({
                    'ids': {'values': ioc_event_ids}
                })
            
            # If 'sigma' not checked, exclude Sigma events
            if 'sigma' not in event_tag_filters and sigma_event_ids:
                tag_must_not_clauses.append({
                    'ids': {'values': sigma_event_ids}
                })
            
            # Apply the exclusion filters
            if tag_must_not_clauses:
                for clause in tag_must_not_clauses:
                    must_clauses.append({
                        'bool': {
                            'must_not': clause
                        }
                    })
        
        # Add noise category filters
        # Logic: By default (no categories checked), HIDE all noise events
        #        When categories ARE checked, ADD those noise categories to results (cumulative with other filters)
        # Noise events have: noise_matched=True and noise_categories=[list]
        
        # Build should clauses for what to include
        should_clauses = []
        
        # Always include non-noise events (events without noise_matched=True)
        should_clauses.append({
            'bool': {
                'must_not': [
                    {'exists': {'field': 'noise_matched'}}
                ]
            }
        })
        
        # If noise categories are checked, also include those specific noise events
        if noise_category_filters:
            should_clauses.append({
                'bool': {
                    'must': [
                        {'term': {'noise_matched': True}},
                        {'terms': {'noise_categories.keyword': noise_category_filters}}
                    ]
                }
            })
        
        # Add the noise filter as a must clause (at least one should match)
        if should_clauses:
            must_clauses.append({
                'bool': {
                    'should': should_clauses,
                    'minimum_should_match': 1
                }
            })
        
        # Build final query
        if must_clauses:
            if len(must_clauses) == 1:
                query = must_clauses[0]
            else:
                query = {
                    'bool': {
                        'must': must_clauses
                    }
                }
        else:
            query = {'match_all': {}}
        
        # Log the final query for debugging
        import json
        logger.info(f"Final OpenSearch query: {json.dumps(query, indent=2)}")
        
        # Get total count (fast - uses count API)
        count_response = client.count(index=index_name, body={'query': query})
        total = count_response['count']
        
        logger.info(f"Query returned {total} total events")
        
        # Calculate pagination
        total_pages = (total + per_page - 1) // per_page if total > 0 else 0
        
        if total == 0 or page > total_pages:
            return jsonify({
                'events': [],
                'total': total,
                'page': page,
                'per_page': per_page,
                'total_pages': total_pages
            })
        
        # OPTIMIZATION: For pages beyond halfway, search in reverse
        # This makes last pages as fast as first pages!
        use_reverse = page > (total_pages / 2)
        
        if use_reverse:
            # Reverse sort order for better performance on last pages
            actual_sort_order = 'asc' if sort_order == 'desc' else 'desc'
            # Calculate page from the end
            reverse_page = total_pages - page + 1
            skip_count = (reverse_page - 1) * per_page
            logger.info(f"Using reverse search for page {page}/{total_pages} (reverse_page={reverse_page})")
        else:
            actual_sort_order = sort_order
            skip_count = (page - 1) * per_page
        
        # Build search body with search_after optimization
        search_body = {
            'query': query,
            'size': per_page,
            'sort': [
                {sort_field: {
                    'order': actual_sort_order,
                    'missing': '_last' if actual_sort_order == 'asc' else '_first',  # Put docs without field at end
                    'unmapped_type': 'date' if sort_field in ['timestamp', 'normalized_timestamp', '@timestamp', 'system_time'] else 'keyword'
                }},
                {'_id': {'order': actual_sort_order}}  # Tie-breaker for consistent pagination
            ],
            '_source': [
                'normalized_timestamp', 'normalized_computer', 'normalized_event_id',
                'source_file', '@timestamp', 'timestamp',
                'event_id', 'computer', 'channel', 'provider_name',
                'host.hostname', 'host.name', 'event.code', 'event.type', 'event.category',
                'process.name', 'process.command_line', 'command_line', 'file_type',
                'analyst_tagged', 'analyst_tagged_by', 'analyst_tagged_at'
            ],
            'track_total_hits': True
        }
        
        # For pages beyond first, we need to skip efficiently
        if skip_count > 0:
            # Use search_after with a skip query to jump directly to position
            # This is faster than iterating through all results
            if skip_count < 10000:
                # Use from/size for pages within 10K limit (most efficient)
                search_body['from'] = skip_count
                response = client.search(index=index_name, body=search_body)
            else:
                # For deep pagination, use PIT + search_after approach
                # First, get a "pointer" to skip position efficiently
                logger.info(f"Deep pagination: skipping {skip_count} records efficiently")
                
                # Use scroll to skip efficiently (larger batches)
                from opensearchpy.helpers import scan
                
                skip_batch_size = 5000  # Skip in large batches
                events_to_skip = skip_count
                last_sort_values = None
                
                # Skip in large batches
                skip_query = {
                    'query': query,
                    'size': skip_batch_size,
                    'sort': search_body['sort'],
                    '_source': False  # Don't fetch data while skipping
                }
                
                while events_to_skip > 0:
                    if last_sort_values:
                        skip_query['search_after'] = last_sort_values
                    
                    skip_response = client.search(index=index_name, body=skip_query)
                    hits = skip_response['hits']['hits']
                    
                    if not hits:
                        break
                    
                    # Take the last hit's sort values
                    last_sort_values = hits[-1]['sort']
                    events_to_skip -= len(hits)
                    
                    if events_to_skip <= 0:
                        break
                
                # Now fetch actual page data using search_after
                if last_sort_values:
                    search_body['search_after'] = last_sort_values
                
                response = client.search(index=index_name, body=search_body)
        else:
            # First page - direct access
            response = client.search(index=index_name, body=search_body)
        
        # Parse results
        events = []
        event_ids = []  # Collect OpenSearch document IDs
        for hit in response['hits']['hits']:
            event_ids.append(hit['_id'])
            source = hit['_source']
            
            # Determine file type
            file_type = source.get('file_type', 'UNKNOWN').upper()
            if not file_type or file_type == 'UNKNOWN':
                source_file = source.get('source_file', '')
                if source_file.endswith('.evtx'):
                    file_type = 'EVTX'
                elif source_file.endswith(('.ndjson', '.json', '.jsonl')):
                    file_type = 'NDJSON'
                elif source_file.endswith('.csv'):
                    file_type = 'CSV'
            
            # Get timestamp
            timestamp = (
                source.get('normalized_timestamp') or
                source.get('@timestamp') or
                source.get('timestamp') or
                source.get('system_time')
            )
            
            # Get computer/hostname
            computer = (
                source.get('normalized_computer') or
                source.get('computer') or
                source.get('host', {}).get('hostname') if isinstance(source.get('host'), dict) else None or
                source.get('host', {}).get('name') if isinstance(source.get('host'), dict) else None or
                'Unknown'
            )
            
            # Get event ID (for NDJSON, show "EDR" instead)
            if file_type == 'NDJSON':
                event_id = 'EDR'
            else:
                # Try multiple field locations for event ID
                event_id = source.get('normalized_event_id')
                if not event_id:
                    event_id = source.get('event_id')
                if not event_id and isinstance(source.get('event'), dict):
                    event_id = source.get('event', {}).get('code')
                if not event_id and isinstance(source.get('event'), dict):
                    event_id = source.get('event', {}).get('type')
                if not event_id:
                    event_id = 'N/A'
            
            # Build description (prioritize command_line for NDJSON)
            description_parts = []
            
            if file_type == 'NDJSON':
                # For NDJSON/EDR events, prioritize command_line
                cmd = None
                if source.get('process', {}).get('command_line'):
                    cmd = source['process']['command_line']
                elif source.get('command_line'):
                    cmd = source.get('command_line')
                
                if cmd:
                    # Truncate for readability
                    if len(cmd) > 120:
                        cmd = cmd[:120] + '...'
                    description_parts.append(cmd)
                elif source.get('process', {}).get('name'):
                    description_parts.append(f"Process: {source['process']['name']}")
                
                # Add event category/type if available
                if source.get('event', {}).get('category'):
                    category = source['event']['category']
                    if not description_parts:
                        description_parts.append(f"Category: {category}")
                    
            elif file_type == 'EVTX':
                # For EVTX events, try to use the event database for enhanced descriptions
                from app.utils.evtx_descriptions import enhance_event_description
                
                channel = source.get('channel')
                provider_name = source.get('provider_name')
                
                # Try to get enhanced description from database
                enhanced_desc = enhance_event_description(
                    event_id=event_id,
                    channel=channel,
                    provider_name=provider_name,
                    original_description=None
                )
                
                # Use enhanced description if available
                if enhanced_desc:
                    description_parts.append(enhanced_desc)
                else:
                    # Fallback to original logic
                    if provider_name:
                        description_parts.append(provider_name)
                    if channel:
                        description_parts.append(f"[{channel}]")
                    if source.get('process', {}).get('name'):
                        description_parts.append(f"Process: {source['process']['name']}")
                    elif source.get('process', {}).get('command_line'):
                        cmd = source['process']['command_line']
                        if len(cmd) > 100:
                            cmd = cmd[:100] + '...'
                        description_parts.append(f"CMD: {cmd}")
            else:
                # For other file types (CSV, IIS, etc.), use original logic
                if source.get('provider_name'):
                    description_parts.append(source['provider_name'])
                if source.get('channel'):
                    description_parts.append(f"[{source['channel']}]")
                if source.get('process', {}).get('name'):
                    description_parts.append(f"Process: {source['process']['name']}")
                elif source.get('process', {}).get('command_line'):
                    cmd = source['process']['command_line']
                    if len(cmd) > 100:
                        cmd = cmd[:100] + '...'
                    description_parts.append(f"CMD: {cmd}")
            
            if not description_parts:
                event_type = source.get('event', {}).get('type') if isinstance(source.get('event'), dict) else None
                if event_type:
                    if isinstance(event_type, list):
                        description_parts.append(f"Type: {', '.join(event_type)}")
                    else:
                        description_parts.append(f"Type: {event_type}")
            
            description = ' - '.join(description_parts) if description_parts else f"Event {event_id}"
            
            events.append({
                'id': hit['_id'],
                'timestamp': timestamp,
                'type': file_type,
                'event_id': event_id,
                'computer': computer,
                'description': description,
                'tagged': source.get('analyst_tagged', False),
                'tagged_by': source.get('analyst_tagged_by'),
                'tagged_at': source.get('analyst_tagged_at'),
                'ioc_types': []  # Will be populated below
            })
        
        # Query database for IOC hits for these events
        if event_ids:
            from models import EventIOCHit, EventSigmaHit
            from main import db
            from sqlalchemy import func
            
            # Get unique IOC types for each event
            ioc_hits = db.session.query(
                EventIOCHit.opensearch_doc_id,
                EventIOCHit.ioc_type,
                EventIOCHit.threat_level
            ).filter(
                EventIOCHit.opensearch_doc_id.in_(event_ids),
                EventIOCHit.case_id == case_id
            ).distinct().all()
            
            # Create lookup dictionary with unique IOC types per event
            from collections import defaultdict
            ioc_lookup = defaultdict(list)
            for hit in ioc_hits:
                ioc_lookup[hit.opensearch_doc_id].append({
                    'type': hit.ioc_type,
                    'threat_level': hit.threat_level
                })
            
            # Get Sigma hit counts and highest severity for each event
            sigma_hits = db.session.query(
                EventSigmaHit.opensearch_doc_id,
                func.count(EventSigmaHit.id).label('hit_count'),
                func.max(
                    db.case(
                        (EventSigmaHit.rule_level == 'critical', 5),
                        (EventSigmaHit.rule_level == 'high', 4),
                        (EventSigmaHit.rule_level == 'medium', 3),
                        (EventSigmaHit.rule_level == 'low', 2),
                        else_=1
                    )
                ).label('max_severity')
            ).filter(
                EventSigmaHit.opensearch_doc_id.in_(event_ids),
                EventSigmaHit.case_id == case_id
            ).group_by(EventSigmaHit.opensearch_doc_id).all()
            
            # Get rule titles for each event (for tooltip)
            sigma_rules_query = db.session.query(
                EventSigmaHit.opensearch_doc_id,
                EventSigmaHit.rule_title,
                EventSigmaHit.rule_level
            ).filter(
                EventSigmaHit.opensearch_doc_id.in_(event_ids),
                EventSigmaHit.case_id == case_id
            ).all()
            
            # Create lookup dictionary for Sigma rules
            from collections import defaultdict
            sigma_rules_lookup = defaultdict(list)
            for rule in sigma_rules_query:
                sigma_rules_lookup[rule.opensearch_doc_id].append({
                    'title': rule.rule_title,
                    'level': rule.rule_level
                })
            
            # Create lookup dictionary for Sigma hits
            sigma_lookup = {}
            severity_map = {5: 'critical', 4: 'high', 3: 'medium', 2: 'low', 1: 'informational'}
            for hit in sigma_hits:
                sigma_lookup[hit.opensearch_doc_id] = {
                    'count': hit.hit_count,
                    'level': severity_map.get(hit.max_severity, 'medium'),
                    'rules': sigma_rules_lookup.get(hit.opensearch_doc_id, [])
                }
            
            # Update events with IOC and Sigma information
            for event in events:
                if event['id'] in ioc_lookup:
                    event['ioc_types'] = ioc_lookup[event['id']]
                if event['id'] in sigma_lookup:
                    event['sigma_count'] = sigma_lookup[event['id']]['count']
                    event['sigma_level'] = sigma_lookup[event['id']]['level']
                    event['sigma_rules'] = sigma_lookup[event['id']]['rules']
        
        # If we used reverse search, reverse the results back
        if use_reverse:
            events = list(reversed(events))
        
        return jsonify({
            'events': events,
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': total_pages,
            'sort_field': sort_field,
            'sort_order': sort_order
        })
        
    except Exception as e:
        logger.error(f"Error searching events: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@search_bp.route('/api/event/<event_id>')
@login_required
def api_get_event(event_id):
    """
    Get full event details by ID
    
    Returns complete event data including all nested fields, IOC hits, and Sigma hits
    """
    try:
        # Get case ID from session
        case_id = session.get('selected_case_id')
        if not case_id:
            return jsonify({'error': 'No case selected'}), 400
        
        # Verify access
        from models import Case
        case = Case.query.get(case_id)
        if not case:
            return jsonify({'error': 'Case not found'}), 404
        
        if current_user.role == 'read-only':
            if case.id != current_user.case_assigned:
                return jsonify({'error': 'Access denied'}), 403
        
        # Get event from OpenSearch - fetch all fields for complete view
        index_name = f"case_{case_id}"
        client = get_opensearch_client()
        
        try:
            response = client.get(index=index_name, id=event_id)
            event = response['_source']
            
            # Query database for IOC hits for this event
            from models import EventIOCHit, EventSigmaHit
            from main import db
            
            ioc_hits = db.session.query(EventIOCHit).filter(
                EventIOCHit.opensearch_doc_id == event_id,
                EventIOCHit.case_id == case_id
            ).all()
            
            # Convert IOC hits to dict format
            ioc_hits_data = []
            for hit in ioc_hits:
                ioc_hits_data.append({
                    'id': hit.id,
                    'ioc_value': hit.ioc_value,
                    'value': hit.ioc_value,  # Alias for frontend compatibility
                    'ioc_type': hit.ioc_type,
                    'ioc_category': hit.ioc_category,
                    'threat_level': hit.threat_level,
                    'field_name': hit.matched_in_field,  # Frontend expects field_name
                    'matched_in_field': hit.matched_in_field,
                    'match_context': hit.match_context,
                    'confidence': hit.confidence,
                    'detected_at': hit.detected_at.isoformat() if hit.detected_at else None
                })
            
            # Query database for Sigma hits for this event
            sigma_hits = db.session.query(EventSigmaHit).filter(
                EventSigmaHit.opensearch_doc_id == event_id,
                EventSigmaHit.case_id == case_id
            ).all()
            
            # Convert Sigma hits to dict format
            sigma_hits_data = []
            for hit in sigma_hits:
                sigma_hits_data.append({
                    'id': hit.id,
                    'sigma_rule_id': hit.sigma_rule_id,
                    'rule_title': hit.rule_title,
                    'rule_level': hit.rule_level,
                    'mitre_tags': hit.mitre_tags,
                    'matched_field': hit.matched_field,
                    'confidence': hit.confidence,
                    'detected_at': hit.detected_at.isoformat() if hit.detected_at else None
                })
            
            # Add IOC and Sigma hits to the event data
            event['ioc_hits'] = ioc_hits_data
            event['sigma_hits'] = sigma_hits_data
            
            return jsonify({
                'id': event_id,
                'event': event
            })
        except NotFoundError:
            return jsonify({'error': 'Event not found'}), 404
        
    except Exception as e:
        logger.error(f"Error fetching event: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@search_bp.route('/api/event/<event_id>/tag', methods=['POST'])
@login_required
def api_tag_event(event_id):
    """
    Tag an event as analyst-selected
    
    Updates the OpenSearch document with analyst_tagged=true and metadata
    """
    try:
        # Get case ID from session
        case_id = session.get('selected_case_id')
        if not case_id:
            return jsonify({'error': 'No case selected'}), 400
        
        # Verify access
        from models import Case
        case = Case.query.get(case_id)
        if not case:
            return jsonify({'error': 'Case not found'}), 404
        
        if current_user.role == 'read-only':
            if case.id != current_user.case_assigned:
                return jsonify({'error': 'Access denied'}), 403
        
        # Update event in OpenSearch
        index_name = f"case_{case_id}"
        client = get_opensearch_client()
        
        try:
            # Update document with analyst tagging metadata
            from datetime import datetime, timezone
            update_body = {
                'doc': {
                    'analyst_tagged': True,
                    'analyst_tagged_by': current_user.username,
                    'analyst_tagged_at': datetime.now(timezone.utc).isoformat()
                }
            }
            
            client.update(index=index_name, id=event_id, body=update_body)
            
            logger.info(f"Event {event_id} tagged by {current_user.username} in case {case_id}")
            
            return jsonify({
                'success': True,
                'message': 'Event tagged successfully'
            })
            
        except NotFoundError:
            return jsonify({'error': 'Event not found'}), 404
        
    except Exception as e:
        logger.error(f"Error tagging event: {e}")
        return jsonify({'error': str(e)}), 500


@search_bp.route('/api/event/<event_id>/untag', methods=['POST'])
@login_required
def api_untag_event(event_id):
    """
    Remove analyst tag from an event
    
    Updates the OpenSearch document with analyst_tagged=false
    """
    try:
        # Get case ID from session
        case_id = session.get('selected_case_id')
        if not case_id:
            return jsonify({'error': 'No case selected'}), 400
        
        # Verify access
        from models import Case
        case = Case.query.get(case_id)
        if not case:
            return jsonify({'error': 'Case not found'}), 404
        
        if current_user.role == 'read-only':
            if case.id != current_user.case_assigned:
                return jsonify({'error': 'Access denied'}), 403
        
        # Update event in OpenSearch
        index_name = f"case_{case_id}"
        client = get_opensearch_client()
        
        try:
            # Update document to remove analyst tagging
            update_body = {
                'doc': {
                    'analyst_tagged': False,
                    'analyst_tagged_by': None,
                    'analyst_tagged_at': None
                }
            }
            
            client.update(index=index_name, id=event_id, body=update_body)
            
            logger.info(f"Event {event_id} untagged by {current_user.username} in case {case_id}")
            
            return jsonify({
                'success': True,
                'message': 'Event tag removed successfully'
            })
            
        except NotFoundError:
            return jsonify({'error': 'Event not found'}), 404
        
    except Exception as e:
        logger.error(f"Error untagging event: {e}")
        return jsonify({'error': str(e)}), 500


@search_bp.route('/api/tagged_events/count')
@login_required
def api_tagged_events_count():
    """
    Get count of tagged events for current case
    
    Returns the number of analyst-tagged events
    """
    try:
        # Get case ID from session
        case_id = session.get('selected_case_id')
        if not case_id:
            return jsonify({'error': 'No case selected'}), 400
        
        # Verify access
        from models import Case
        case = Case.query.get(case_id)
        if not case:
            return jsonify({'error': 'Case not found'}), 404
        
        if current_user.role == 'read-only':
            if case.id != current_user.case_assigned:
                return jsonify({'error': 'Access denied'}), 403
        
        # Query OpenSearch for tagged events count
        index_name = f"case_{case_id}"
        client = get_opensearch_client()
        
        try:
            # Check if index exists
            if not client.indices.exists(index=index_name):
                return jsonify({
                    'success': True,
                    'count': 0
                })
            
            # Count tagged events
            query = {
                'query': {
                    'term': {'analyst_tagged': True}
                }
            }
            
            count_response = client.count(index=index_name, body=query)
            
            return jsonify({
                'success': True,
                'count': count_response['count']
            })
            
        except Exception as e:
            logger.error(f"Error counting tagged events: {e}")
            return jsonify({'error': str(e)}), 500
        
    except Exception as e:
        logger.error(f"Error in tagged events count: {e}")
        return jsonify({'error': str(e)}), 500


@search_bp.route('/api/tagged_events')
@login_required
def api_get_tagged_events():
    """
    Get all tagged events for current case
    
    Used for automated hunting and analyst review workflows
    Returns simplified event data for all tagged events
    """
    try:
        # Get case ID from session
        case_id = session.get('selected_case_id')
        if not case_id:
            return jsonify({'error': 'No case selected'}), 400
        
        # Verify access
        from models import Case
        case = Case.query.get(case_id)
        if not case:
            return jsonify({'error': 'Case not found'}), 404
        
        if current_user.role == 'read-only':
            if case.id != current_user.case_assigned:
                return jsonify({'error': 'Access denied'}), 403
        
        # Query OpenSearch for all tagged events
        index_name = f"case_{case_id}"
        client = get_opensearch_client()
        
        try:
            # Check if index exists
            if not client.indices.exists(index=index_name):
                return jsonify({
                    'success': True,
                    'events': [],
                    'total': 0
                })
            
            # Query for tagged events
            query = {
                'query': {
                    'term': {'analyst_tagged': True}
                },
                'sort': [
                    {'analyst_tagged_at': {'order': 'desc'}}
                ],
                'size': 10000  # Max tagged events to return
            }
            
            response = client.search(index=index_name, body=query)
            
            # Parse results
            tagged_events = []
            for hit in response['hits']['hits']:
                source = hit['_source']
                
                # Get basic event info
                timestamp = (
                    source.get('normalized_timestamp') or
                    source.get('@timestamp') or
                    source.get('timestamp')
                )
                
                computer = (
                    source.get('normalized_computer') or
                    source.get('computer') or
                    'Unknown'
                )
                
                event_id = source.get('normalized_event_id') or source.get('event_id') or 'N/A'
                
                tagged_events.append({
                    'id': hit['_id'],
                    'timestamp': timestamp,
                    'computer': computer,
                    'event_id': event_id,
                    'tagged_by': source.get('analyst_tagged_by'),
                    'tagged_at': source.get('analyst_tagged_at'),
                    'file_type': source.get('file_type', 'UNKNOWN')
                })
            
            return jsonify({
                'success': True,
                'events': tagged_events,
                'total': len(tagged_events)
            })
            
        except Exception as e:
            logger.error(f"Error fetching tagged events: {e}")
            return jsonify({'error': str(e)}), 500
        
    except Exception as e:
        logger.error(f"Error in get tagged events: {e}")
        return jsonify({'error': str(e)}), 500
