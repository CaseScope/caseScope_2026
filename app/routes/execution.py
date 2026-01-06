"""
Execution Artifacts Routes
View and search execution artifacts (Prefetch, LNK shortcuts, JumpLists)
"""

from flask import Blueprint, render_template, jsonify, request, session
from flask_login import login_required, current_user
from opensearchpy import OpenSearch
from opensearchpy.exceptions import NotFoundError
import logging
from utils.opensearch_client import get_opensearch_client

logger = logging.getLogger(__name__)

execution_bp = Blueprint('execution', __name__, url_prefix='/execution')


@execution_bp.route('/')
@execution_bp.route('/artifacts')
@login_required
def artifacts():
    """
    Main execution artifacts page
    """
    # Get selected case from session
    case_id = session.get('selected_case_id')
    
    if not case_id:
        return render_template('execution/artifacts.html', 
                             case_id=None,
                             error='No case selected. Please select a case first.')
    
    # Verify user has access to this case
    from models import Case
    case = Case.query.get(case_id)
    
    if not case:
        return render_template('execution/artifacts.html',
                             case_id=None,
                             error='Case not found.')
    
    # Check permissions
    if current_user.role == 'read-only':
        if case.id != current_user.case_assigned:
            return render_template('execution/artifacts.html',
                                 case_id=None,
                                 error='Access denied to this case.')
    
    return render_template('execution/artifacts.html',
                         case=case,
                         case_id=case_id)


@execution_bp.route('/api/stats')
@login_required
def api_execution_stats():
    """
    Get execution artifacts statistics
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
    
    index_name = f"case_{case_id}_execution"
    client = get_opensearch_client()
    
    try:
        # Check if execution index exists
        if not client.indices.exists(index=index_name):
            return jsonify({
                'total_artifacts': 0,
                'lnk_count': 0,
                'prefetch_count': 0,
                'top_executables': [],
                'artifact_types': [],
                'message': 'No execution data indexed yet.'
            })
        
        # Get aggregations for stats
        response = client.search(
            index=index_name,
            body={
                "query": {"match_all": {}},
                "size": 0,
                "track_total_hits": True,
                "aggs": {
                    "total_artifacts": {
                        "value_count": {"field": "@timestamp"}
                    },
                    "artifact_types": {
                        "terms": {"field": "artifact_type.keyword", "size": 10}
                    },
                    "event_types": {
                        "terms": {"field": "event_type.keyword", "size": 10}
                    },
                    "top_executables": {
                        "terms": {"field": "executable.keyword", "size": 15}
                    }
                }
            }
        )
        
        # Extract counts by artifact type
        artifact_buckets = response['aggregations']['artifact_types']['buckets']
        lnk_count = next((b['doc_count'] for b in artifact_buckets if b['key'] == 'lnk'), 0)
        prefetch_count = next((b['doc_count'] for b in artifact_buckets if b['key'] == 'prefetch'), 0)
        
        stats = {
            'total_artifacts': response['aggregations']['total_artifacts']['value'],
            'lnk_count': lnk_count,
            'prefetch_count': prefetch_count,
            'top_executables': [
                {'executable': bucket['key'], 'count': bucket['doc_count']}
                for bucket in response['aggregations']['top_executables']['buckets']
            ],
            'artifact_types': [
                {'type': bucket['key'], 'count': bucket['doc_count']}
                for bucket in response['aggregations']['artifact_types']['buckets']
            ],
            'event_types': [
                {'type': bucket['key'], 'count': bucket['doc_count']}
                for bucket in response['aggregations']['event_types']['buckets']
            ]
        }
        
        return jsonify(stats)
        
    except NotFoundError:
        return jsonify({
            'total_artifacts': 0,
            'lnk_count': 0,
            'prefetch_count': 0,
            'top_executables': [],
            'artifact_types': [],
            'message': 'Execution index not found.'
        })
    except Exception as e:
        logger.error(f"Error getting execution stats: {e}", exc_info=True)
        return jsonify({'error': f'Failed to get stats: {str(e)}'}), 500


@execution_bp.route('/api/artifacts')
@login_required
def api_execution_artifacts():
    """
    API endpoint for execution artifact search
    
    Query Parameters:
    - q: Search query (executable, target path, etc.)
    - page: Page number (default: 1)
    - per_page: Results per page (default: 50, max: 100)
    - sort: Sort field (default: @timestamp)
    - order: Sort order (asc/desc, default: desc)
    - type: Filter by artifact type (lnk, prefetch)
    - user: Filter by source_user
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
    artifact_type = request.args.get('type', '').strip().lower()
    user_filter = request.args.get('user', '').strip()
    
    # Calculate offset
    from_offset = (page - 1) * per_page
    
    # Build OpenSearch query
    index_name = f"case_{case_id}_execution"
    
    client = get_opensearch_client()
    
    # Check if execution index exists
    try:
        if not client.indices.exists(index=index_name):
            return jsonify({
                'artifacts': [],
                'total': 0,
                'page': page,
                'per_page': per_page,
                'total_pages': 0,
                'has_next': False,
                'has_prev': False,
                'message': 'No execution data indexed yet for this case.'
            })
    except Exception as e:
        logger.error(f"Error checking index {index_name}: {e}")
        return jsonify({'error': 'Failed to check execution index'}), 500
    
    # Build query
    filters = []
    
    # Add artifact type filter
    if artifact_type:
        filters.append({"term": {"artifact_type.keyword": artifact_type}})
    
    # Add user filter
    if user_filter:
        filters.append({"term": {"source_user.keyword": user_filter}})
    
    if query:
        # Search in multiple fields
        query_body = {
            "bool": {
                "should": [
                    {"wildcard": {"executable": f"*{query}*"}},
                    {"wildcard": {"target_path": f"*{query}*"}},
                    {"wildcard": {"working_directory": f"*{query}*"}},
                    {"match": {"executable": {"query": query, "fuzziness": "AUTO"}}},
                    {"match": {"target_path": {"query": query, "fuzziness": "AUTO"}}}
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
                "track_total_hits": True
            }
        )
        
        total = response['hits']['total']['value']
        artifacts = [hit['_source'] for hit in response['hits']['hits']]
        
        total_pages = (total + per_page - 1) // per_page
        
        return jsonify({
            'artifacts': artifacts,
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': total_pages,
            'has_next': page < total_pages,
            'has_prev': page > 1
        })
        
    except NotFoundError:
        return jsonify({
            'artifacts': [],
            'total': 0,
            'page': page,
            'per_page': per_page,
            'total_pages': 0,
            'has_next': False,
            'has_prev': False,
            'message': 'Execution index not found.'
        })
    except Exception as e:
        logger.error(f"Error searching execution artifacts: {e}", exc_info=True)
        return jsonify({'error': f'Search failed: {str(e)}'}), 500


@execution_bp.route('/api/users')
@login_required
def api_get_users():
    """
    Get list of users who have execution artifacts
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
    
    # Get distinct users from execution files
    users = db.session.query(
        CaseFile.source_user,
        db.func.count(CaseFile.id).label('file_count')
    ).filter(
        CaseFile.case_id == case_id,
        CaseFile.target_index.like('%execution%'),
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

