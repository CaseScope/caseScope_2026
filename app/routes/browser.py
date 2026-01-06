"""
Browser History Routes
View and search browser artifacts (Chrome, Edge, Firefox history)
"""

from flask import Blueprint, render_template, jsonify, request, session
from flask_login import login_required, current_user
from opensearchpy import OpenSearch
from opensearchpy.exceptions import NotFoundError
import logging
from utils.opensearch_client import get_opensearch_client

logger = logging.getLogger(__name__)

browser_bp = Blueprint('browser', __name__, url_prefix='/browser')


@browser_bp.route('/')
@browser_bp.route('/history')
@login_required
def history():
    """
    Main browser history page
    """
    # Get selected case from session
    case_id = session.get('selected_case_id')
    
    if not case_id:
        return render_template('browser/history.html', 
                             case_id=None,
                             error='No case selected. Please select a case first.')
    
    # Verify user has access to this case
    from models import Case
    case = Case.query.get(case_id)
    
    if not case:
        return render_template('browser/history.html',
                             case_id=None,
                             error='Case not found.')
    
    # Check permissions
    if current_user.role == 'read-only':
        if case.id != current_user.case_assigned:
            return render_template('browser/history.html',
                                 case_id=None,
                                 error='Access denied to this case.')
    
    return render_template('browser/history.html',
                         case=case,
                         case_id=case_id)


@browser_bp.route('/api/users')
@login_required
def api_get_users():
    """
    Get list of users who have browser data
    """
    case_id = session.get('selected_case_id')
    
    if not case_id:
        return jsonify({'error': 'No case selected'}), 400
    
    from models import Case, CaseFile
    from main import db
    
    case = Case.query.get(case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    
    if current_user.role == 'read-only':
        if case.id != current_user.case_assigned:
            return jsonify({'error': 'Access denied'}), 403
    
    # Get distinct users from browser files
    users = db.session.query(
        CaseFile.source_user,
        db.func.count(CaseFile.id).label('file_count')
    ).filter(
        CaseFile.case_id == case_id,
        CaseFile.target_index.like('%browser%'),
        CaseFile.source_user.isnot(None)
    ).group_by(
        CaseFile.source_user
    ).order_by(
        db.func.count(CaseFile.id).desc()
    ).all()
    
    user_list = [
        {'username': user.source_user, 'file_count': user.file_count}
        for user in users
    ]
    
    return jsonify({'users': user_list})


@browser_bp.route('/api/events')
@login_required
def api_browser_events():
    """
    API endpoint for browser event search
    
    Query Parameters:
    - q: Search query (URL, title, domain)
    - page: Page number (default: 1)
    - per_page: Results per page (default: 50, max: 100)
    - sort: Sort field (default: @timestamp)
    - order: Sort order (asc/desc, default: desc)
    - browser: Filter by browser type (chrome, edge, firefox)
    """
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
    query = request.args.get('q', '').strip()
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 50, type=int), 100)
    sort_field = request.args.get('sort', '@timestamp')
    sort_order = request.args.get('order', 'desc')
    browser_filter = request.args.get('browser', '').strip().lower()
    
    # Calculate offset
    from_offset = (page - 1) * per_page
    
    # Build OpenSearch query
    index_name = f"case_{case_id}_browser"
    
    client = get_opensearch_client()
    
    # Check if browser index exists
    try:
        if not client.indices.exists(index=index_name):
            return jsonify({
                'events': [],
                'total': 0,
                'page': page,
                'per_page': per_page,
                'total_pages': 0,
                'has_next': False,
                'has_prev': False,
                'message': 'No browser data indexed yet for this case.'
            })
    except Exception as e:
        logger.error(f"Error checking index {index_name}: {e}")
        return jsonify({'error': 'Failed to check browser index'}), 500
    
    # Build query
    if query:
        # Search in URL, title, domain fields
        query_body = {
            "bool": {
                "should": [
                    {"wildcard": {"url": f"*{query}*"}},
                    {"wildcard": {"title": f"*{query}*"}},
                    {"wildcard": {"domain": f"*{query}*"}},
                    {"match": {"url": {"query": query, "fuzziness": "AUTO"}}},
                    {"match": {"title": {"query": query, "fuzziness": "AUTO"}}}
                ],
                "minimum_should_match": 1
            }
        }
    else:
        query_body = {"match_all": {}}
    
    # Add browser filter if specified
    if browser_filter:
        if "bool" not in query_body:
            query_body = {"bool": {"must": [{"match_all": {}}]}}
        if "filter" not in query_body["bool"]:
            query_body["bool"]["filter"] = []
        
        query_body["bool"]["filter"].append({
            "term": {"browser.keyword": browser_filter}
        })
    
    # Execute search
    try:
        response = client.search(
            index=index_name,
            body={
                "query": query_body,
                "from": from_offset,
                "size": per_page,
                "sort": [{sort_field: {"order": sort_order}}],
                "_source": True,
                "track_total_hits": True  # Get accurate total beyond 10K
            }
        )
        
        total = response['hits']['total']['value']
        events = [hit['_source'] for hit in response['hits']['hits']]
        
        total_pages = (total + per_page - 1) // per_page
        
        return jsonify({
            'events': events,
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': total_pages,
            'has_next': page < total_pages,
            'has_prev': page > 1
        })
        
    except NotFoundError:
        return jsonify({
            'events': [],
            'total': 0,
            'page': page,
            'per_page': per_page,
            'total_pages': 0,
            'has_next': False,
            'has_prev': False,
            'message': 'Browser index not found.'
        })
    except Exception as e:
        logger.error(f"Error searching browser events: {e}", exc_info=True)
        return jsonify({'error': f'Search failed: {str(e)}'}), 500


@browser_bp.route('/api/downloads')
@login_required
def api_downloads():
    """
    Get list of file downloads from browser history
    
    Query Parameters:
    - page: Page number (default: 1)
    - per_page: Results per page (default: 50, max: 100)
    """
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
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 50, type=int), 100)
    
    # Calculate offset
    from_offset = (page - 1) * per_page
    
    index_name = f"case_{case_id}_browser"
    client = get_opensearch_client()
    
    try:
        # Check if browser index exists
        if not client.indices.exists(index=index_name):
            return jsonify({
                'downloads': [],
                'total': 0,
                'page': page,
                'per_page': per_page,
                'total_pages': 0,
                'has_next': False,
                'has_prev': False,
                'message': 'No browser data indexed yet for this case.'
            })
        
        # Search for download events
        response = client.search(
            index=index_name,
            body={
                "query": {
                    "term": {"event_type.keyword": "browser_download"}
                },
                "from": from_offset,
                "size": per_page,
                "sort": [{"@timestamp": {"order": "desc"}}],
                "_source": True,
                "track_total_hits": True
            }
        )
        
        total = response['hits']['total']['value']
        downloads_raw = [hit['_source'] for hit in response['hits']['hits']]
        
        # Get hostname from main case index (EVTX events have 'computer' field)
        main_index = f"case_{case_id}"
        hostname = 'Unknown'
        
        try:
            # Query main index for a sample event to get computer name
            hostname_query = client.search(
                index=main_index,
                body={
                    "size": 1,
                    "query": {
                        "exists": {"field": "computer"}
                    },
                    "_source": ["computer"]
                }
            )
            
            if hostname_query['hits']['total']['value'] > 0:
                hostname = hostname_query['hits']['hits'][0]['_source'].get('computer', 'Unknown')
        except Exception as e:
            logger.warning(f"Could not retrieve hostname from main index: {e}")
        
        # Enrich downloads with hostname and CaseFile metadata
        from models import CaseFile
        from main import db
        
        downloads = []
        for download in downloads_raw:
            source_file = download.get('source_file')
            
            # Add hostname to every download
            download['hostname'] = hostname
            
            # Look up CaseFile to get source_user (already in file path, but this is cleaner)
            if source_file:
                case_file = CaseFile.query.filter_by(
                    case_id=case_id,
                    filename=source_file
                ).first()
                
                if case_file and case_file.source_user:
                    download['case_file_source_user'] = case_file.source_user
            
            downloads.append(download)
        
        total_pages = (total + per_page - 1) // per_page
        
        return jsonify({
            'downloads': downloads,
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': total_pages,
            'has_next': page < total_pages,
            'has_prev': page > 1
        })
        
    except NotFoundError:
        return jsonify({
            'downloads': [],
            'total': 0,
            'page': page,
            'per_page': per_page,
            'total_pages': 0,
            'has_next': False,
            'has_prev': False,
            'message': 'Browser index not found.'
        })
    except Exception as e:
        logger.error(f"Error fetching downloads: {e}", exc_info=True)
        return jsonify({'error': f'Failed to fetch downloads: {str(e)}'}), 500


@browser_bp.route('/api/stats')
@login_required
def api_browser_stats():
    """
    Get browser statistics (top domains, browsers, timeline)
    Supports filtering by user and browser type
    
    Query Parameters:
    - user: Filter by source_user
    - browser: Filter by browser type
    """
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
    
    # Get filter parameters
    user_filter = request.args.get('user', '').strip()
    browser_filter = request.args.get('browser', '').strip().lower()
    
    index_name = f"case_{case_id}_browser"
    client = get_opensearch_client()
    
    try:
        # Build query with filters
        query_filters = []
        if user_filter:
            query_filters.append({"term": {"source_user.keyword": user_filter}})
        if browser_filter:
            query_filters.append({"term": {"browser.keyword": browser_filter}})
        
        query_body = {"match_all": {}}
        if query_filters:
            query_body = {
                "bool": {
                    "filter": query_filters
                }
            }
        
        # Get aggregations for stats
        response = client.search(
            index=index_name,
            body={
                "query": query_body,
                "size": 0,
                "track_total_hits": True,  # Get accurate count beyond 10K
                "aggs": {
                    "total_visits": {
                        "value_count": {"field": "@timestamp"}
                    },
                    "top_urls": {
                        "terms": {"field": "url.keyword", "size": 15}
                    },
                    "browser_types": {
                        "terms": {"field": "browser.keyword", "size": 10}
                    }
                }
            }
        )
        
        stats = {
            'total_visits': response['aggregations']['total_visits']['value'],
            'top_urls': [
                {'url': bucket['key'], 'count': bucket['doc_count']}
                for bucket in response['aggregations']['top_urls']['buckets']
            ],
            'browser_types': [
                {'browser': bucket['key'], 'count': bucket['doc_count']}
                for bucket in response['aggregations']['browser_types']['buckets']
            ]
        }
        
        # If user is selected, add user-specific stats
        if user_filter:
            # Get browser breakdown for this user
            user_stats_response = client.search(
                index=index_name,
                body={
                    "query": {
                        "bool": {
                            "filter": [{"term": {"source_user.keyword": user_filter}}]
                        }
                    },
                    "size": 0,
                    "track_total_hits": True,  # Get accurate count beyond 10K
                    "aggs": {
                        "total_events": {
                            "value_count": {"field": "@timestamp"}
                        },
                        "browsers": {
                            "terms": {"field": "browser.keyword", "size": 10}
                        }
                    }
                }
            )
            
            stats['user_stats'] = {
                'username': user_filter,
                'total_events': user_stats_response['aggregations']['total_events']['value'],
                'browsers': [
                    {'browser': bucket['key'], 'count': bucket['doc_count']}
                    for bucket in user_stats_response['aggregations']['browsers']['buckets']
                ]
            }
        
        return jsonify(stats)
        
    except NotFoundError:
        return jsonify({
            'total_visits': 0,
            'top_urls': [],
            'browser_types': [],
            'message': 'No browser data indexed yet.'
        })
    except Exception as e:
        logger.error(f"Error getting browser stats: {e}", exc_info=True)
        return jsonify({'error': f'Failed to get stats: {str(e)}'}), 500

