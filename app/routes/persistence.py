"""Persistence Routes - Scheduled Tasks, WMI"""
from flask import Blueprint, render_template, jsonify, request, session
from flask_login import login_required, current_user
from opensearchpy import OpenSearch
from opensearchpy.exceptions import NotFoundError
import logging

logger = logging.getLogger(__name__)
persistence_bp = Blueprint('persistence', __name__, url_prefix='/persistence')

def get_opensearch_client():
    from config import Config
    return OpenSearch(hosts=[{'host': Config.OPENSEARCH_HOST, 'port': Config.OPENSEARCH_PORT}], use_ssl=Config.OPENSEARCH_USE_SSL, verify_certs=False, ssl_show_warn=False, timeout=30)

@persistence_bp.route('/')
@persistence_bp.route('/<int:case_id>')
@login_required
def mechanisms(case_id=None):
    if not case_id:
        case_id = session.get('selected_case_id')
    if not case_id:
        return render_template('persistence/mechanisms.html', case_id=None, case=None, error='No case selected.')
    from models import Case
    case = Case.query.get(case_id)
    if not case:
        return render_template('persistence/mechanisms.html', case_id=None, case=None, error='Case not found.')
    if current_user.role == 'read-only' and case.id != current_user.case_assigned:
        return render_template('persistence/mechanisms.html', case_id=None, case=None, error='Access denied.')
    return render_template('persistence/mechanisms.html', case=case, case_id=case_id)

@persistence_bp.route('/api/stats/<int:case_id>')
@login_required
def api_stats(case_id):
    try:
        client = get_opensearch_client()
        index_name = f'case_{case_id}_persistence'
        
        # Get total count
        total_response = client.count(index=index_name, body={"query": {"match_all": {}}})
        total = total_response.get('count', 0)
        
        # Get breakdown by event_type
        agg_body = {
            "size": 0,
            "aggs": {
                "by_type": {
                    "terms": {
                        "field": "event_type",
                        "size": 10
                    }
                }
            }
        }
        
        agg_response = client.search(index=index_name, body=agg_body)
        buckets = agg_response.get('aggregations', {}).get('by_type', {}).get('buckets', [])
        
        task_count = 0
        wmi_count = 0
        
        for bucket in buckets:
            if bucket['key'] == 'scheduled_task':
                task_count = bucket['doc_count']
            elif bucket['key'] in ['wmi_subscription', 'wmi_event_filter', 'wmi_consumer']:
                wmi_count += bucket['doc_count']
        
        # For now, mark tasks with suspicious patterns as high risk
        # TODO: Implement risk scoring based on task patterns
        high_risk = 0  # Placeholder
        
        return jsonify({
            'total': total,
            'task_count': task_count,
            'wmi_count': wmi_count,
            'high_risk': high_risk
        })
        
    except NotFoundError:
        return jsonify({'total': 0, 'task_count': 0, 'wmi_count': 0, 'high_risk': 0})
    except Exception as e:
        logger.error(f"Error getting persistence stats: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@persistence_bp.route('/api/events/<int:case_id>')
@login_required
def api_events(case_id):
    try:
        client = get_opensearch_client()
        index_name = f'case_{case_id}_persistence'
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
