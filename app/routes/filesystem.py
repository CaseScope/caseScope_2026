"""
Filesystem Timeline Routes
View and search MFT (Master File Table) data
"""

from flask import Blueprint, render_template, jsonify, request, session
from flask_login import login_required, current_user
from opensearchpy import OpenSearch
from opensearchpy.exceptions import NotFoundError
import logging

logger = logging.getLogger(__name__)

filesystem_bp = Blueprint('filesystem', __name__, url_prefix='/filesystem')


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


@filesystem_bp.route('/')
@filesystem_bp.route('/timeline')
@login_required
def timeline():
    """
    Main filesystem timeline page
    """
    case_id = session.get('selected_case_id')
    
    if not case_id:
        return render_template('filesystem/timeline.html', 
                             case_id=None,
                             error='No case selected. Please select a case first.')
    
    from models import Case
    case = Case.query.get(case_id)
    
    if not case:
        return render_template('filesystem/timeline.html',
                             case_id=None,
                             error='Case not found.')
    
    if current_user.role == 'read-only':
        if case.id != current_user.case_assigned:
            return render_template('filesystem/timeline.html',
                                 case_id=None,
                                 error='Access denied to this case.')
    
    return render_template('filesystem/timeline.html',
                         case=case,
                         case_id=case_id)


@filesystem_bp.route('/api/stats')
@login_required
def api_filesystem_stats():
    """
    Get filesystem statistics
    """
    case_id = session.get('selected_case_id')
    
    if not case_id:
        return jsonify({'error': 'No case selected'}), 400
    
    from models import Case
    case = Case.query.get(case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    
    if current_user.role == 'read-only':
        if case.id != current_user.case_assigned:
            return jsonify({'error': 'Access denied'}), 403
    
    index_name = f"case_{case_id}_filesystem"
    client = get_opensearch_client()
    
    try:
        if not client.indices.exists(index=index_name):
            return jsonify({
                'total_entries': 0,
                'files': 0,
                'directories': 0,
                'deleted': 0,
                'message': 'No filesystem data indexed yet.'
            })
        
        response = client.search(
            index=index_name,
            body={
                "query": {"match_all": {}},
                "size": 0,
                "track_total_hits": True,
                "aggs": {
                    "total_entries": {"value_count": {"field": "@timestamp"}},
                    "files": {"filter": {"term": {"is_directory": False}}},
                    "directories": {"filter": {"term": {"is_directory": True}}},
                    "deleted": {"filter": {"term": {"in_use": False}}},
                    "top_extensions": {"terms": {"field": "extension.keyword", "size": 15}}
                }
            }
        )
        
        stats = {
            'total_entries': response['aggregations']['total_entries']['value'],
            'files': response['aggregations']['files']['doc_count'],
            'directories': response['aggregations']['directories']['doc_count'],
            'deleted': response['aggregations']['deleted']['doc_count'],
            'top_extensions': [
                {'extension': b['key'], 'count': b['doc_count']}
                for b in response['aggregations']['top_extensions']['buckets']
            ]
        }
        
        return jsonify(stats)
        
    except NotFoundError:
        return jsonify({
            'total_entries': 0,
            'files': 0,
            'directories': 0,
            'deleted': 0,
            'message': 'Filesystem index not found.'
        })
    except Exception as e:
        logger.error(f"Error getting filesystem stats: {e}", exc_info=True)
        return jsonify({'error': f'Failed to get stats: {str(e)}'}), 500


@filesystem_bp.route('/api/entries')
@login_required
def api_filesystem_entries():
    """
    API endpoint for filesystem entry search
    
    Query Parameters:
    - q: Search query (filename, path, extension)
    - page: Page number (default: 1)
    - per_page: Results per page (default: 50, max: 100)
    - sort: Sort field (default: @timestamp)
    - order: Sort order (asc/desc, default: desc)
    - type: Filter by type (file/directory)
    - deleted: Show deleted files (true/false)
    """
    case_id = session.get('selected_case_id')
    
    if not case_id:
        return jsonify({'error': 'No case selected'}), 400
    
    from models import Case
    case = Case.query.get(case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    
    if current_user.role == 'read-only':
        if case.id != current_user.case_assigned:
            return jsonify({'error': 'Access denied'}), 403
    
    # Get params
    query = request.args.get('q', '').strip()
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 50, type=int), 100)
    sort_field = request.args.get('sort', 'created_fn')
    sort_order = request.args.get('order', 'desc')
    entry_type = request.args.get('type', '').strip()
    show_deleted = request.args.get('deleted', 'false').lower() == 'true'
    
    from_offset = (page - 1) * per_page
    index_name = f"case_{case_id}_filesystem"
    client = get_opensearch_client()
    
    try:
        if not client.indices.exists(index=index_name):
            return jsonify({
                'entries': [],
                'total': 0,
                'page': page,
                'per_page': per_page,
                'total_pages': 0,
                'has_next': False,
                'has_prev': False,
                'message': 'No filesystem data indexed yet.'
            })
    except Exception as e:
        return jsonify({'error': 'Failed to check filesystem index'}), 500
    
    # Build query
    filters = []
    
    if entry_type == 'file':
        filters.append({"term": {"is_directory": False}})
    elif entry_type == 'directory':
        filters.append({"term": {"is_directory": True}})
    
    if not show_deleted:
        filters.append({"term": {"in_use": True}})
    
    if query:
        query_body = {
            "bool": {
                "should": [
                    {"wildcard": {"file_name": f"*{query}*"}},
                    {"wildcard": {"extension": f"*{query}*"}},
                    {"match": {"file_name": {"query": query, "fuzziness": "AUTO"}}}
                ],
                "minimum_should_match": 1
            }
        }
        if filters:
            query_body["bool"]["filter"] = filters
    else:
        if filters:
            query_body = {"bool": {"filter": filters}}
        else:
            query_body = {"match_all": {}}
    
    try:
        response = client.search(
            index=index_name,
            body={
                "query": query_body,
                "from": from_offset,
                "size": per_page,
                "sort": [{sort_field: {"order": sort_order}}],
                "_source": True,
                "track_total_hits": True
            }
        )
        
        total = response['hits']['total']['value']
        entries = [hit['_source'] for hit in response['hits']['hits']]
        total_pages = (total + per_page - 1) // per_page
        
        return jsonify({
            'entries': entries,
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': total_pages,
            'has_next': page < total_pages,
            'has_prev': page > 1
        })
        
    except NotFoundError:
        return jsonify({
            'entries': [],
            'total': 0,
            'page': page,
            'per_page': per_page,
            'total_pages': 0,
            'has_next': False,
            'has_prev': False,
            'message': 'Filesystem index not found.'
        })
    except Exception as e:
        logger.error(f"Error searching filesystem entries: {e}", exc_info=True)
        return jsonify({'error': f'Search failed: {str(e)}'}), 500

