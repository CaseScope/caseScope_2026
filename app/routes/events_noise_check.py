"""
Events Noise Check Route
Checks if an event matches noise filter rules and returns which rules matched
"""

from flask import Blueprint, jsonify, request
from flask_login import login_required
from utils.noise_filter import check_event_against_filters
from opensearchpy import OpenSearch
from main import app
import logging

logger = logging.getLogger(__name__)

events_noise_check_bp = Blueprint('events_noise_check', __name__, url_prefix='/api/events')


@events_noise_check_bp.route('/<event_id>/noise-check', methods=['GET'])
@login_required
def check_event_noise(event_id):
    """
    Check if an event matches any noise filter rules
    
    Returns:
        JSON with noise filter matches:
        {
            "is_noise": true/false,
            "matched_rules": [
                {
                    "rule_name": "ConnectWise Automate",
                    "category": "RMM Tools",
                    "pattern": "labtech,ltsvc,lttray",
                    "matched_fields": ["process.executable", "process.command_line"]
                }
            ],
            "total_matches": 2
        }
    """
    try:
        # Get case_id from query params
        case_id = request.args.get('case_id', type=int)
        
        if not case_id:
            return jsonify({'error': 'case_id is required'}), 400
        
        # Get OpenSearch client
        os_client = OpenSearch(
            app.config.get('OPENSEARCH_HOSTS', ['http://localhost:9200']),
            http_auth=(
                app.config.get('OPENSEARCH_USER', 'admin'),
                app.config.get('OPENSEARCH_PASSWORD', 'admin')
            ),
            use_ssl=app.config.get('OPENSEARCH_USE_SSL', False),
            verify_certs=False,
            ssl_show_warn=False
        )
        
        # Construct index name
        index_name = f"case_{case_id}"
        
        # Fetch the event
        try:
            result = os_client.get(index=index_name, id=event_id)
            event_data = result['_source']
        except Exception as e:
            logger.error(f"Error fetching event {event_id} from {index_name}: {e}")
            return jsonify({'error': 'Event not found'}), 404
        
        # Check event against noise filters
        noise_matches = check_event_against_filters(event_data, return_details=True)
        
        return jsonify({
            'is_noise': noise_matches['is_noise'],
            'matched_rules': noise_matches['matched_rules'],
            'total_matches': noise_matches['total_matches']
        })
        
    except Exception as e:
        logger.error(f"Error checking event noise: {e}")
        return jsonify({'error': str(e)}), 500

