#!/usr/bin/env python3
"""
Progress API Routes
===================

API endpoints for tracking long-running operation progress.

Endpoints:
- GET /case/<case_id>/progress/<operation> - Get current progress

Author: CaseScope
Version: 2.0.0
"""

from flask import Blueprint, jsonify, request
from flask_login import login_required
import logging

logger = logging.getLogger(__name__)

# Create blueprint
progress_bp = Blueprint('progress', __name__)


@progress_bp.route('/case/<int:case_id>/progress/<operation>', methods=['GET'])
@login_required
def get_operation_progress(case_id, operation):
    """
    Get current progress for an operation.
    
    Args:
        case_id: Case ID
        operation: Operation type ('clear_metadata', 'index', 'reindex', 'resigma', 'reioc')
        
    Returns:
        JSON: {
            'status': 'running'|'completed'|'failed'|'not_found',
            'current_phase': int,
            'total_phases': int,
            'phases': [phase_data],
            'elapsed_time': float,
            'error_message': str (if failed)
        }
    """
    from progress_tracker import get_progress
    
    progress = get_progress(case_id, operation)
    
    if progress is None:
        return jsonify({
            'status': 'not_found',
            'message': 'No progress tracking for this operation'
        })
    
    return jsonify(progress)

