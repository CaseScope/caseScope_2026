"""Communications Routes - Email, Teams/Skype, Notifications"""
from flask import Blueprint, render_template, jsonify, request, session
from flask_login import login_required, current_user
from opensearchpy import OpenSearch
from opensearchpy.exceptions import NotFoundError
import logging

logger = logging.getLogger(__name__)
communications_bp = Blueprint('communications', __name__, url_prefix='/communications')

def get_opensearch_client():
    from config import Config
    return OpenSearch(
        hosts=[{'host': Config.OPENSEARCH_HOST, 'port': Config.OPENSEARCH_PORT}],
        use_ssl=Config.OPENSEARCH_USE_SSL, verify_certs=False, ssl_show_warn=False, timeout=30
    )

@communications_bp.route('/')
@communications_bp.route('/<int:case_id>')
@login_required
def messages(case_id=None):
    if not case_id:
        case_id = session.get('selected_case_id')
    if not case_id:
        return render_template('communications/messages.html', case_id=None, case=None, error='No case selected.')
    from models import Case
    case = Case.query.get(case_id)
    if not case:
        return render_template('communications/messages.html', case_id=None, case=None, error='Case not found.')
    if current_user.role == 'read-only' and case.id != current_user.case_assigned:
        return render_template('communications/messages.html', case_id=None, case=None, error='Access denied.')
    return render_template('communications/messages.html', case=case, case_id=case_id)

@communications_bp.route('/api/stats/<int:case_id>')
@login_required
def api_stats(case_id):
    try:
        client = get_opensearch_client()
        index_name = f'case_{case_id}_comms'
        total_response = client.count(index=index_name, body={"query": {"match_all": {}}})
        total = total_response.get('count', 0)
        agg_query = {"size": 0, "aggs": {"by_type": {"terms": {"field": "event_type.keyword", "size": 10}}}}
        agg_response = client.search(index=index_name, body=agg_query)
        buckets = agg_response.get('aggregations', {}).get('by_type', {}).get('buckets', [])
        email_count = sum(b['doc_count'] for b in buckets if 'email' in b['key'].lower() or 'pst' in b['key'].lower())
        chat_count = sum(b['doc_count'] for b in buckets if 'teams' in b['key'].lower() or 'skype' in b['key'].lower())
        notification_count = sum(b['doc_count'] for b in buckets if 'notification' in b['key'].lower())
        return jsonify({'total': total, 'email_count': email_count, 'chat_count': chat_count, 'notification_count': notification_count})
    except NotFoundError:
        return jsonify({'total': 0, 'email_count': 0, 'chat_count': 0, 'notification_count': 0})
    except Exception as e:
        logger.error(f"Error: {e}")
        return jsonify({'error': str(e)}), 500

@communications_bp.route('/api/events/<int:case_id>')
@login_required
def api_events(case_id):
    try:
        client = get_opensearch_client()
        index_name = f'case_{case_id}_comms'
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))
        query_text = request.args.get('q', '')
        query = {"multi_match": {"query": query_text, "fields": ["subject", "email_from", "email_to", "message_body"]}} if query_text else {"match_all": {}}
        from_offset = (page - 1) * per_page
        search_body = {"query": query, "from": from_offset, "size": per_page, "sort": [{"@timestamp": {"order": "desc"}}]}
        response = client.search(index=index_name, body=search_body)
        hits = response.get('hits', {})
        total = hits.get('total', {}).get('value', 0)
        events = [hit['_source'] for hit in hits.get('hits', [])]
        total_pages = (total + per_page - 1) // per_page
        return jsonify({'events': events, 'total': total, 'page': page, 'per_page': per_page, 'total_pages': total_pages, 'has_prev': page > 1, 'has_next': page < total_pages})
    except NotFoundError:
        return jsonify({'events': [], 'total': 0, 'page': 1, 'total_pages': 0})
    except Exception as e:
        logger.error(f"Error: {e}")
        return jsonify({'error': str(e)}), 500
