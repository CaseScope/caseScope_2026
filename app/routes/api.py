"""
API Routes
JSON endpoints for AJAX requests
"""

from flask import Blueprint, jsonify
from flask_login import login_required

from models import db, CaseFile

api_bp = Blueprint('api', __name__, url_prefix='/api')


@api_bp.route('/case/<int:case_id>/status')
@login_required
def case_file_status(case_id):
    """Get file statuses for live updates"""
    files = db.session.query(CaseFile).filter_by(
        case_id=case_id, 
        is_deleted=False, 
        is_hidden=False
    ).all()
    
    return jsonify({
        'files': [{
            'id': f.id,
            'status': f.file_state or 'Unknown',  # v2.2.0: Use file_state instead
            'event_count': f.event_count or 0,
            'violation_count': f.violation_count or 0,
            'ioc_event_count': f.ioc_event_count or 0
        } for f in files]
    })
