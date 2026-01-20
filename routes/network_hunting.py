"""Network Hunting API routes for CaseScope"""
import logging
from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user

from models.database import db
from models.case import Case
from models.pcap_file import PcapFile, PcapFileStatus
from models import network_log

logger = logging.getLogger(__name__)

network_hunting_bp = Blueprint('network_hunting', __name__, url_prefix='/api/network')


@network_hunting_bp.route('/hunting/<case_uuid>/stats', methods=['GET'])
@login_required
def get_network_stats(case_uuid):
    """Get network log statistics for a case"""
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        stats = network_log.get_network_stats(case.id)
        stats['success'] = True
        return jsonify(stats)
    except Exception as e:
        logger.exception(f"Error getting network stats for case {case_uuid}")
        return jsonify({'success': False, 'error': str(e)}), 500


@network_hunting_bp.route('/hunting/<case_uuid>/pcap-stats', methods=['GET'])
@login_required
def get_pcap_log_stats(case_uuid):
    """Get log counts per PCAP file"""
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        stats = network_log.get_pcap_stats(case.id)
        pcap_files = {p.id: p for p in PcapFile.query.filter_by(case_uuid=case_uuid, is_archive=False).all()}
        for stat in stats:
            pcap = pcap_files.get(stat['pcap_id'])
            if pcap:
                stat['filename'] = pcap.filename
                stat['hostname'] = pcap.hostname
                stat['indexed_at'] = pcap.indexed_at.isoformat() if pcap.indexed_at else None
        return jsonify({'success': True, 'pcaps': stats})
    except Exception as e:
        logger.exception(f"Error getting PCAP stats for case {case_uuid}")
        return jsonify({'success': False, 'error': str(e)}), 500


@network_hunting_bp.route('/hunting/<case_uuid>/logs', methods=['GET'])
@login_required
def query_network_logs(case_uuid):
    """Query network logs with filters and pagination"""
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        log_type = request.args.get('log_type', 'conn')
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 50, type=int), 500)
        search = request.args.get('search', '').strip()
        pcap_id = request.args.get('pcap_id', type=int)
        src_ip = request.args.get('src_ip', '').strip()
        dst_ip = request.args.get('dst_ip', '').strip()
        time_start = request.args.get('time_start', '').strip()
        time_end = request.args.get('time_end', '').strip()
        order_by = request.args.get('order_by', 'timestamp')
        order_dir = request.args.get('order_dir', 'DESC')
        result = network_log.query_logs(
            case_id=case.id, log_type=log_type, page=page, per_page=per_page,
            search=search, pcap_id=pcap_id, src_ip=src_ip, dst_ip=dst_ip,
            time_start=time_start if time_start else None,
            time_end=time_end if time_end else None,
            order_by=order_by, order_dir=order_dir
        )
        return jsonify(result)
    except Exception as e:
        logger.exception(f"Error querying network logs for case {case_uuid}")
        return jsonify({'success': False, 'error': str(e)}), 500


@network_hunting_bp.route('/hunting/<case_uuid>/search', methods=['GET'])
@login_required
def search_all_network_logs(case_uuid):
    """Search across all network log types"""
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        search = request.args.get('q', '').strip()
        if not search:
            return jsonify({'success': False, 'error': 'Search term required'}), 400
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 50, type=int), 500)
        pcap_id = request.args.get('pcap_id', type=int)
        result = network_log.search_all_logs(case_id=case.id, search=search, page=page, per_page=per_page, pcap_id=pcap_id)
        return jsonify(result)
    except Exception as e:
        logger.exception(f"Error searching network logs for case {case_uuid}")
        return jsonify({'success': False, 'error': str(e)}), 500


@network_hunting_bp.route('/hunting/<case_uuid>/pcaps', methods=['GET'])
@login_required
def get_indexed_pcaps(case_uuid):
    """Get list of PCAPs that have been indexed"""
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        pcaps = PcapFile.query.filter(
            PcapFile.case_uuid == case_uuid, PcapFile.is_archive == False,
            PcapFile.status == PcapFileStatus.DONE
        ).order_by(PcapFile.uploaded_at.desc()).all()
        result = [{'id': p.id, 'filename': p.filename, 'hostname': p.hostname,
            'logs_indexed': p.logs_indexed or 0,
            'indexed_at': p.indexed_at.isoformat() if p.indexed_at else None,
            'has_data': (p.logs_indexed or 0) > 0} for p in pcaps]
        return jsonify({'success': True, 'pcaps': result, 'total': len(result)})
    except Exception as e:
        logger.exception(f"Error getting indexed PCAPs for case {case_uuid}")
        return jsonify({'success': False, 'error': str(e)}), 500


@network_hunting_bp.route('/hunting/<int:pcap_id>/index', methods=['POST'])
@login_required
def index_pcap_logs(pcap_id):
    """Trigger indexing of Zeek logs for a PCAP file"""
    if current_user.permission_level == 'viewer':
        return jsonify({'success': False, 'error': 'Viewers cannot index logs'}), 403
    try:
        pcap_file = db.session.get(PcapFile, pcap_id)
        if not pcap_file:
            return jsonify({'success': False, 'error': 'PCAP file not found'}), 404
        if pcap_file.status != PcapFileStatus.DONE:
            return jsonify({'success': False, 'error': 'PCAP must be processed with Zeek first'}), 400
        from tasks.pcap_tasks import index_zeek_logs
        task = index_zeek_logs.delay(pcap_id)
        return jsonify({'success': True, 'pcap_id': pcap_id, 'task_id': task.id, 'message': 'Indexing queued'})
    except Exception as e:
        logger.exception(f"Error queuing index for PCAP {pcap_id}")
        return jsonify({'success': False, 'error': str(e)}), 500


@network_hunting_bp.route('/hunting/<case_uuid>/index-all', methods=['POST'])
@login_required
def index_all_pcaps(case_uuid):
    """Index all processed PCAPs that have not been indexed yet"""
    if current_user.permission_level == 'viewer':
        return jsonify({'success': False, 'error': 'Viewers cannot index logs'}), 403
    try:
        case = Case.get_by_uuid(case_uuid)
        if not case:
            return jsonify({'success': False, 'error': 'Case not found'}), 404
        pcaps = PcapFile.query.filter(
            PcapFile.case_uuid == case_uuid, PcapFile.is_archive == False,
            PcapFile.status == PcapFileStatus.DONE, PcapFile.indexed_at == None
        ).all()
        if not pcaps:
            return jsonify({'success': False, 'error': 'No PCAPs pending indexing'}), 400
        from tasks.pcap_tasks import index_zeek_logs
        queued = [{'pcap_id': p.id, 'filename': p.filename, 'task_id': index_zeek_logs.delay(p.id).id} for p in pcaps]
        return jsonify({'success': True, 'queued_count': len(queued), 'queued': queued})
    except Exception as e:
        logger.exception(f"Error queuing index-all for case {case_uuid}")
        return jsonify({'success': False, 'error': str(e)}), 500
