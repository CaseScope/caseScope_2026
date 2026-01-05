"""Remote Sessions Routes - RDP Cache"""
from flask import Blueprint, render_template, jsonify, request, session
from flask_login import login_required, current_user
from opensearchpy import OpenSearch
from opensearchpy.exceptions import NotFoundError
import logging

logger = logging.getLogger(__name__)
remote_bp = Blueprint('remote', __name__, url_prefix='/remote')

def get_opensearch_client():
    from config import Config
    return OpenSearch(hosts=[{'host': Config.OPENSEARCH_HOST, 'port': Config.OPENSEARCH_PORT}], use_ssl=Config.OPENSEARCH_USE_SSL, verify_certs=False, ssl_show_warn=False, timeout=30)

@remote_bp.route('/')
@remote_bp.route('/<int:case_id>')
@login_required
def sessions(case_id=None):
    if not case_id:
        case_id = session.get('selected_case_id')
    if not case_id:
        return render_template('remote/sessions.html', case_id=None, case=None, error='No case selected.')
    from models import Case
    case = Case.query.get(case_id)
    if not case:
        return render_template('remote/sessions.html', case_id=None, case=None, error='Case not found.')
    if current_user.role == 'read-only' and case.id != current_user.case_assigned:
        return render_template('remote/sessions.html', case_id=None, case=None, error='Access denied.')
    return render_template('remote/sessions.html', case=case, case_id=case_id)

@remote_bp.route('/api/stats/<int:case_id>')
@login_required
def api_stats(case_id):
    try:
        client = get_opensearch_client()
        index_name = f'case_{case_id}_remote'
        total_response = client.count(index=index_name, body={"query": {"match_all": {}}})
        return jsonify({'total': total_response.get('count', 0), 'tile_count': 0, 'file_count': 0, 'total_size': 0})
    except NotFoundError:
        return jsonify({'total': 0, 'tile_count': 0, 'file_count': 0, 'total_size': 0})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@remote_bp.route('/api/events/<int:case_id>')
@login_required
def api_events(case_id):
    try:
        client = get_opensearch_client()
        index_name = f'case_{case_id}_remote'
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))
        from_offset = (page - 1) * per_page
        search_body = {"query": {"match_all": {}}, "from": from_offset, "size": per_page, "sort": [{"@timestamp": {"order": "desc"}}]}
        response = client.search(index=index_name, body=search_body)
        hits = response.get('hits', {})
        total = hits.get('total', {}).get('value', 0)
        events = [hit['_source'] for hit in hits.get('hits', [])]
        total_pages = (total + per_page - 1) // per_page
        return jsonify({'events': events, 'total': total, 'page': page, 'total_pages': total_pages, 'has_prev': page > 1, 'has_next': page < total_pages})
    except NotFoundError:
        return jsonify({'events': [], 'total': 0, 'page': 1, 'total_pages': 0})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
