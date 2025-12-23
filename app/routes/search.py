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
        sort_field = request.args.get('sort', 'normalized_timestamp')
        sort_order = request.args.get('order', 'desc')
        
        # Get file type filters
        file_types_param = request.args.get('file_types', '')
        file_type_filters = [ft.strip().upper() for ft in file_types_param.split(',') if ft.strip()]
        
        logger.info(f"Search request - query: '{query_string}', file_types_param: '{file_types_param}', file_type_filters: {file_type_filters}")
        
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
                {sort_field: {'order': actual_sort_order}},
                {'_id': {'order': actual_sort_order}}  # Tie-breaker for consistent pagination
            ],
            '_source': [
                'normalized_timestamp', 'normalized_computer', 'normalized_event_id',
                'source_file', '@timestamp', 'timestamp',
                'event_id', 'computer', 'channel', 'provider_name',
                'host.hostname', 'host.name', 'event.code', 'event.type', 'event.category',
                'process.name', 'process.command_line', 'command_line', 'file_type'
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
        for hit in response['hits']['hits']:
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
                    
            else:
                # For EVTX and other types, use original logic
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
                'tagged': False
            })
        
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
    
    Returns complete event data including all nested fields
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
            
            return jsonify({
                'id': event_id,
                'event': event
            })
        except NotFoundError:
            return jsonify({'error': 'Event not found'}), 404
        
    except Exception as e:
        logger.error(f"Error fetching event: {e}")
        return jsonify({'error': str(e)}), 500
