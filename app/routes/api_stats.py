"""
API endpoints for real-time statistics
"""
from flask import Blueprint, jsonify
from flask_login import login_required
import logging

api_stats_bp = Blueprint('api_stats', __name__)
logger = logging.getLogger(__name__)


@api_stats_bp.route('/api/case/<int:case_id>/stats')
@login_required
def case_stats(case_id):
    """Get real-time case statistics"""
    from main import db, Case, CaseFile, SigmaViolation, IOC
    from sqlalchemy import func
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    
    # File statistics
    total_files = db.session.query(CaseFile).filter_by(
        case_id=case_id, is_deleted=False, is_hidden=False
    ).count()
    
    indexed_files = db.session.query(CaseFile).filter_by(
        case_id=case_id, is_deleted=False, is_hidden=False, is_indexed=True
    ).count()
    
    # Files being processed (not completed) - v2.2.0: use file_state_manager
    import file_statistics as fs
    processing_files = db.session.query(CaseFile).filter(
        CaseFile.case_id == case_id,
        CaseFile.is_deleted == False,
        CaseFile.is_hidden == False,
        CaseFile.celery_task_id != None  # Files actively in queue
    ).count()
    
    # Disk space
    total_size = db.session.query(func.sum(CaseFile.file_size)).filter_by(
        case_id=case_id, is_deleted=False, is_hidden=False
    ).scalar() or 0
    disk_space_mb = round(total_size / 1024 / 1024, 2)
    
    # Event statistics
    total_events = db.session.query(func.sum(CaseFile.event_count)).filter_by(
        case_id=case_id, is_deleted=False, is_hidden=False
    ).scalar() or 0
    
    # SIGMA violations (count from CaseFile.violation_count)
    total_sigma = db.session.query(func.sum(CaseFile.violation_count)).filter_by(
        case_id=case_id, is_deleted=False, is_hidden=False
    ).scalar() or 0
    
    # Events with IOCs (count from CaseFile.ioc_event_count)
    total_ioc_events = db.session.query(func.sum(CaseFile.ioc_event_count)).filter_by(
        case_id=case_id, is_deleted=False, is_hidden=False
    ).scalar() or 0
    
    # Number of IOCs tracked
    total_iocs = db.session.query(IOC).filter_by(
        case_id=case_id, is_active=True
    ).count()
    
    # Total systems identified
    from main import System
    total_systems = db.session.query(System).filter_by(
        case_id=case_id, hidden=False
    ).count()
    
    return jsonify({
        'success': True,
        'file_stats': {
            'total_files': total_files,
            'indexed_files': indexed_files,
            'processing_files': processing_files,
            'disk_space_mb': disk_space_mb
        },
        'event_stats': {
            'total_events': int(total_events),
            'total_sigma': int(total_sigma),
            'total_ioc_events': int(total_ioc_events),
            'total_iocs': total_iocs,
            'total_systems': total_systems
        }
    })

