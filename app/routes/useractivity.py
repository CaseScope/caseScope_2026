"""
User Activity Routes
View and search user activity artifacts (Jump Lists, LNK shortcuts)
"""

from flask import Blueprint, render_template, jsonify, request, session
from flask_login import login_required, current_user
from opensearchpy import OpenSearch
from opensearchpy.exceptions import NotFoundError
import logging

logger = logging.getLogger(__name__)

useractivity_bp = Blueprint('useractivity', __name__, url_prefix='/useractivity')


def get_opensearch_client():
    """Get OpenSearch client"""
    from config import Config
    return OpenSearch(
        hosts=[{'host': Config.OPENSEARCH_HOST, 'port': Config.OPENSEARCH_PORT}],
        use_ssl=Config.OPENSEARCH_USE_SSL,
        verify_certs=False,
        ssl_show_warn=False,
        timeout=30
    )


@useractivity_bp.route('/')
@useractivity_bp.route('/<int:case_id>')
@login_required
def shortcuts(case_id=None):
    """Main user activity page"""
    # Get case from parameter or session
    if not case_id:
        case_id = session.get('selected_case_id')
    
    if not case_id:
        return render_template('useractivity/shortcuts.html', 
                             case_id=None, case=None,
                             error='No case selected. Please select a case first.')
    
    from models import Case
    case = Case.query.get(case_id)
    
    if not case:
        return render_template('useractivity/shortcuts.html',
                             case_id=None, case=None,
                             error='Case not found.')
    
    # Check permissions
    if current_user.role == 'read-only' and case.id != current_user.case_assigned:
        return render_template('useractivity/shortcuts.html',
                             case_id=None, case=None,
                             error='Access denied to this case.')
    
    return render_template('useractivity/shortcuts.html',
                         case=case, case_id=case_id)


@useractivity_bp.route('/api/stats/<int:case_id>')
@login_required
def api_stats(case_id):
    """Get statistics for user activity"""
    try:
        client = get_opensearch_client()
        index_name = f'case_{case_id}_useractivity'
        
        # Get total count
        total_response = client.count(index=index_name, body={"query": {"match_all": {}}})
        total = total_response.get('count', 0)
        
        # Get counts by type
        agg_query = {
            "size": 0,
            "aggs": {
                "by_type": {
                    "terms": {"field": "event_type.keyword", "size": 10}
                }
            }
        }
        
        agg_response = client.search(index=index_name, body=agg_query)
        buckets = agg_response.get('aggregations', {}).get('by_type', {}).get('buckets', [])
        
        jumplist_count = sum(b['doc_count'] for b in buckets if 'jump' in b['key'].lower())
        lnk_count = sum(b['doc_count'] for b in buckets if 'lnk' in b['key'].lower())
        
        # Get unique files count
        unique_files_query = {
            "size": 0,
            "aggs": {
                "unique_files": {
                    "cardinality": {"field": "file_path.keyword"}
                }
            }
        }
        
        unique_response = client.search(index=index_name, body=unique_files_query)
        unique_files = unique_response.get('aggregations', {}).get('unique_files', {}).get('value', 0)
        
        return jsonify({
            'total': total,
            'jumplist_count': jumplist_count,
            'lnk_count': lnk_count,
            'unique_files': unique_files
        })
        
    except NotFoundError:
        return jsonify({'total': 0, 'jumplist_count': 0, 'lnk_count': 0, 'unique_files': 0})
    except Exception as e:
        logger.error(f"Error getting user activity stats: {e}")
        return jsonify({'error': str(e)}), 500


@useractivity_bp.route('/api/events/<int:case_id>')
@login_required
def api_events(case_id):
    """Get paginated user activity events"""
    try:
        client = get_opensearch_client()
        index_name = f'case_{case_id}_useractivity'
        
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))
        query_text = request.args.get('q', '')
        artifact_type = request.args.get('type', '')
        sort_field = request.args.get('sort', '@timestamp')
        sort_order = request.args.get('order', 'desc')
        
        # Build query
        query = {"match_all": {}}
        
        if query_text:
            query = {
                "multi_match": {
                    "query": query_text,
                    "fields": ["file_name", "file_path", "target_path", "application"]
                }
            }
        
        # Add filters
        filters = []
        if artifact_type:
            filters.append({"match": {"event_type": artifact_type}})
        
        if filters:
            query = {"bool": {"must": query, "filter": filters}}
        
        # Execute search
        from_offset = (page - 1) * per_page
        
        search_body = {
            "query": query,
            "from": from_offset,
            "size": per_page,
            "sort": [{sort_field: {"order": sort_order}}]
        }
        
        response = client.search(index=index_name, body=search_body)
        
        hits = response.get('hits', {})
        total = hits.get('total', {}).get('value', 0)
        events = [hit['_source'] for hit in hits.get('hits', [])]
        
        total_pages = (total + per_page - 1) // per_page
        
        return jsonify({
            'events': events,
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': total_pages,
            'has_prev': page > 1,
            'has_next': page < total_pages
        })
        
    except NotFoundError:
        return jsonify({'events': [], 'total': 0, 'page': 1, 'total_pages': 0})
    except Exception as e:
        logger.error(f"Error searching user activity: {e}")
        return jsonify({'error': str(e)}), 500


@useractivity_bp.route('/api/users/<int:case_id>')
@login_required
def api_users(case_id):
    """Get list of users"""
    try:
        client = get_opensearch_client()
        index_name = f'case_{case_id}_useractivity'
        
        query = {
            "size": 0,
            "aggs": {
                "users": {
                    "terms": {"field": "user.keyword", "size": 100}
                }
            }
        }
        
        response = client.search(index=index_name, body=query)
        buckets = response.get('aggregations', {}).get('users', {}).get('buckets', [])
        users = [b['key'] for b in buckets]
        
        return jsonify({'users': users})
        
    except NotFoundError:
        return jsonify({'users': []})
    except Exception as e:
        logger.error(f"Error getting users: {e}")
        return jsonify({'error': str(e)}), 500

