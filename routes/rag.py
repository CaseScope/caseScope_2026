"""RAG API Routes for CaseScope

Provides API endpoints for:
- Pattern management
- Pattern discovery
- Related event hunting
- Timeline generation
- OpenCTI sync
"""

import logging
from datetime import datetime
from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user

from models.database import db
from models.case import Case

logger = logging.getLogger(__name__)

rag_bp = Blueprint('rag', __name__, url_prefix='/api/rag')


# ============================================================================
# PATTERN MANAGEMENT
# ============================================================================

@rag_bp.route('/patterns')
@login_required
def list_patterns():
    """List all attack patterns"""
    from models.rag import AttackPattern
    
    try:
        source = request.args.get('source')
        enabled_only = request.args.get('enabled', 'true').lower() == 'true'
        
        query = AttackPattern.query
        
        if source:
            query = query.filter_by(source=source)
        if enabled_only:
            query = query.filter_by(enabled=True)
        
        patterns = query.order_by(AttackPattern.name).all()
        
        return jsonify({
            'success': True,
            'count': len(patterns),
            'patterns': [p.to_dict() for p in patterns]
        })
        
    except Exception as e:
        logger.error(f"[RAG API] Error listing patterns: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@rag_bp.route('/patterns/<int:pattern_id>')
@login_required
def get_pattern(pattern_id):
    """Get a specific pattern"""
    from models.rag import AttackPattern
    
    pattern = AttackPattern.query.get(pattern_id)
    if not pattern:
        return jsonify({'success': False, 'error': 'Pattern not found'}), 404
    
    return jsonify({
        'success': True,
        'pattern': pattern.to_dict()
    })


@rag_bp.route('/patterns/<int:pattern_id>/toggle', methods=['POST'])
@login_required
def toggle_pattern(pattern_id):
    """Enable/disable a pattern"""
    from models.rag import AttackPattern
    
    pattern = AttackPattern.query.get(pattern_id)
    if not pattern:
        return jsonify({'success': False, 'error': 'Pattern not found'}), 404
    
    pattern.enabled = not pattern.enabled
    db.session.commit()
    
    return jsonify({
        'success': True,
        'pattern_id': pattern_id,
        'enabled': pattern.enabled
    })


# ============================================================================
# PATTERN DISCOVERY
# ============================================================================

@rag_bp.route('/patterns/discover', methods=['POST'])
@login_required
def discover_patterns():
    """Start pattern discovery task for a case"""
    from tasks.rag_tasks import rag_discover_patterns
    
    data = request.json or {}
    case_id = data.get('case_id')
    
    if not case_id:
        return jsonify({'success': False, 'error': 'case_id required'}), 400
    
    # Get case to verify it exists and get UUID
    case = Case.query.get(case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    pattern_ids = data.get('pattern_ids')  # Optional: specific patterns
    
    task = rag_discover_patterns.delay(
        case_id=case_id,
        case_uuid=case.uuid,
        pattern_ids=pattern_ids
    )
    
    return jsonify({
        'success': True,
        'task_id': task.id,
        'case_id': case_id
    })


# ============================================================================
# RELATED EVENT HUNTING
# ============================================================================

@rag_bp.route('/hunt/related', methods=['POST'])
@login_required
def hunt_related():
    """Start related event hunting task"""
    from tasks.rag_tasks import rag_hunt_related
    
    data = request.json or {}
    case_id = data.get('case_id')
    
    if not case_id:
        return jsonify({'success': False, 'error': 'case_id required'}), 400
    
    case = Case.query.get(case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    task = rag_hunt_related.delay(
        case_id=case_id,
        case_uuid=case.uuid,
        include_ioc=data.get('include_ioc', True),
        include_analyst=data.get('include_analyst', True),
        include_sigma_high=data.get('include_sigma_high', True),
        time_window_hours=data.get('time_window_hours', 24)
    )
    
    return jsonify({
        'success': True,
        'task_id': task.id,
        'case_id': case_id
    })


# ============================================================================
# TIMELINE GENERATION
# ============================================================================

@rag_bp.route('/timeline/generate', methods=['POST'])
@login_required
def generate_timeline():
    """Start timeline generation task"""
    from tasks.rag_tasks import rag_generate_timeline
    
    data = request.json or {}
    case_id = data.get('case_id')
    
    if not case_id:
        return jsonify({'success': False, 'error': 'case_id required'}), 400
    
    case = Case.query.get(case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    task = rag_generate_timeline.delay(
        case_id=case_id,
        case_uuid=case.uuid,
        include_sigma=data.get('include_sigma', True),
        include_ioc=data.get('include_ioc', True),
        include_patterns=data.get('include_patterns', True),
        include_analyst=data.get('include_analyst', True)
    )
    
    return jsonify({
        'success': True,
        'task_id': task.id,
        'case_id': case_id
    })


# ============================================================================
# TASK STATUS
# ============================================================================

@rag_bp.route('/status/<task_id>')
@login_required
def get_task_status(task_id):
    """Get RAG task status"""
    from celery.result import AsyncResult
    from tasks.celery_tasks import celery_app
    
    result = AsyncResult(task_id, app=celery_app)
    
    if result.state == 'PENDING':
        return jsonify({'state': 'pending', 'progress': 0})
    elif result.state == 'PROGRESS':
        return jsonify({
            'state': 'progress',
            'progress': result.info.get('progress', 0),
            'status': result.info.get('status', ''),
            'meta': result.info
        })
    elif result.state == 'SUCCESS':
        return jsonify({
            'state': 'completed',
            'result': result.result
        })
    elif result.state == 'FAILURE':
        return jsonify({
            'state': 'failed',
            'error': str(result.info)
        })
    else:
        return jsonify({
            'state': result.state.lower(),
            'info': str(result.info) if result.info else None
        })


# ============================================================================
# CAMPAIGN DETECTION
# ============================================================================

@rag_bp.route('/campaigns/detect', methods=['POST'])
@login_required
def detect_campaigns():
    """Start campaign detection task for a case"""
    from tasks.rag_tasks import rag_detect_campaigns
    
    data = request.json or {}
    case_id = data.get('case_id')
    
    if not case_id:
        return jsonify({'success': False, 'error': 'case_id required'}), 400
    
    case = Case.query.get(case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    task = rag_detect_campaigns.delay(
        case_id=case_id,
        case_uuid=case.uuid
    )
    
    return jsonify({
        'success': True,
        'task_id': task.id,
        'case_id': case_id
    })


@rag_bp.route('/campaigns/<int:case_id>')
@login_required
def get_campaigns(case_id):
    """Get detected campaigns for a case"""
    from models.rag import AttackCampaign
    
    campaigns = AttackCampaign.query.filter_by(case_id=case_id).order_by(
        AttackCampaign.severity.desc(),
        AttackCampaign.confidence_score.desc()
    ).all()
    
    return jsonify({
        'success': True,
        'count': len(campaigns),
        'campaigns': [c.to_dict() for c in campaigns]
    })


@rag_bp.route('/campaigns/<int:campaign_id>/review', methods=['POST'])
@login_required
def review_campaign(campaign_id):
    """Review a campaign (analyst verdict)"""
    from models.rag import AttackCampaign
    
    campaign = AttackCampaign.query.get(campaign_id)
    if not campaign:
        return jsonify({'success': False, 'error': 'Campaign not found'}), 404
    
    data = request.json or {}
    verdict = data.get('verdict')
    notes = data.get('notes', '')
    
    if verdict not in ['confirmed', 'false_positive', 'needs_review']:
        return jsonify({'success': False, 'error': 'Invalid verdict'}), 400
    
    campaign.set_analyst_review(
        username=current_user.username,
        verdict=verdict,
        notes=notes
    )
    db.session.commit()
    
    return jsonify({
        'success': True,
        'campaign_id': campaign_id,
        'verdict': verdict
    })


# ============================================================================
# PATTERN MATCHES (aggregated view)
# ============================================================================

@rag_bp.route('/matches/<int:case_id>')
@login_required
def get_pattern_matches(case_id):
    """Get pattern matches for a case - aggregated by pattern"""
    from models.rag import PatternMatch, AttackPattern
    
    # Get aggregated view first
    aggregated = db.session.query(
        PatternMatch.pattern_id,
        AttackPattern.name,
        AttackPattern.mitre_technique,
        AttackPattern.severity,
        db.func.count(PatternMatch.id).label('match_count'),
        db.func.count(db.distinct(PatternMatch.source_host)).label('host_count'),
        db.func.avg(PatternMatch.confidence_score).label('avg_confidence'),
        db.func.min(PatternMatch.first_event_time).label('first_seen'),
        db.func.max(PatternMatch.last_event_time).label('last_seen')
    ).join(
        AttackPattern, PatternMatch.pattern_id == AttackPattern.id
    ).filter(
        PatternMatch.case_id == case_id
    ).group_by(
        PatternMatch.pattern_id,
        AttackPattern.name,
        AttackPattern.mitre_technique,
        AttackPattern.severity
    ).order_by(
        db.desc('match_count')
    ).all()
    
    aggregated_list = []
    for row in aggregated:
        aggregated_list.append({
            'pattern_id': row.pattern_id,
            'pattern_name': row.name,
            'mitre_technique': row.mitre_technique,
            'severity': row.severity,
            'match_count': row.match_count,
            'host_count': row.host_count,
            'avg_confidence': round(row.avg_confidence, 2) if row.avg_confidence else 0,
            'first_seen': row.first_seen.isoformat() if row.first_seen else None,
            'last_seen': row.last_seen.isoformat() if row.last_seen else None
        })
    
    # Also get total raw count
    total_matches = PatternMatch.query.filter_by(case_id=case_id).count()
    
    return jsonify({
        'success': True,
        'total_matches': total_matches,
        'aggregated_count': len(aggregated_list),
        'aggregated': aggregated_list
    })


@rag_bp.route('/matches/<int:case_id>/details/<int:pattern_id>')
@login_required
def get_pattern_match_details(case_id, pattern_id):
    """Get detailed matches for a specific pattern with per-host breakdown"""
    from models.rag import PatternMatch, AttackPattern
    
    # Get the pattern definition
    pattern = AttackPattern.query.get(pattern_id)
    if not pattern:
        return jsonify({'success': False, 'error': 'Pattern not found'}), 404
    
    # Get matches
    matches = PatternMatch.query.filter_by(
        case_id=case_id,
        pattern_id=pattern_id
    ).order_by(
        PatternMatch.confidence_score.desc()
    ).limit(100).all()
    
    # Build per-host breakdown
    host_breakdown = {}
    for match in matches:
        host = match.source_host or 'Unknown'
        if host not in host_breakdown:
            host_breakdown[host] = {
                'count': 0,
                'first_seen': None,
                'last_seen': None,
                'users': set()
            }
        host_breakdown[host]['count'] += 1
        if match.affected_users:
            host_breakdown[host]['users'].update(match.affected_users)
        if match.first_event_time:
            if not host_breakdown[host]['first_seen'] or match.first_event_time < host_breakdown[host]['first_seen']:
                host_breakdown[host]['first_seen'] = match.first_event_time
        if match.last_event_time:
            if not host_breakdown[host]['last_seen'] or match.last_event_time > host_breakdown[host]['last_seen']:
                host_breakdown[host]['last_seen'] = match.last_event_time
    
    # Convert to serializable format
    host_list = []
    for host, data in sorted(host_breakdown.items(), key=lambda x: x[1]['count'], reverse=True):
        host_list.append({
            'host': host,
            'count': data['count'],
            'users': list(data['users'])[:10],
            'first_seen': data['first_seen'].isoformat() if data['first_seen'] else None,
            'last_seen': data['last_seen'].isoformat() if data['last_seen'] else None
        })
    
    # Build search terms for event lookup
    search_terms = []
    if pattern.required_event_ids:
        search_terms.extend(pattern.required_event_ids)
    if pattern.name:
        # Add key terms from pattern name
        for term in pattern.name.lower().split():
            if len(term) > 3 and term not in ['with', 'from', 'into', 'the', 'and']:
                search_terms.append(term)
    
    return jsonify({
        'success': True,
        'pattern': {
            'id': pattern.id,
            'name': pattern.name,
            'description': pattern.description,
            'mitre_tactic': pattern.mitre_tactic,
            'mitre_technique': pattern.mitre_technique,
            'severity': pattern.severity,
            'source': pattern.source,
            'required_event_ids': pattern.required_event_ids,
            'required_channels': pattern.required_channels
        },
        'total_matches': len(matches),
        'host_count': len(host_list),
        'hosts': host_list,
        'search_terms': search_terms[:5],
        'matches': [m.to_dict() for m in matches[:20]]
    })


@rag_bp.route('/matches/<int:match_id>/review', methods=['POST'])
@login_required
def review_match(match_id):
    """Review a pattern match (analyst verdict)"""
    from models.rag import PatternMatch
    
    match = PatternMatch.query.get(match_id)
    if not match:
        return jsonify({'success': False, 'error': 'Match not found'}), 404
    
    data = request.json or {}
    verdict = data.get('verdict')
    notes = data.get('notes', '')
    
    if verdict not in ['confirmed', 'false_positive', 'needs_review']:
        return jsonify({'success': False, 'error': 'Invalid verdict'}), 400
    
    match.set_analyst_review(
        username=current_user.username,
        verdict=verdict,
        notes=notes
    )
    db.session.commit()
    
    return jsonify({
        'success': True,
        'match_id': match_id,
        'verdict': verdict
    })


@rag_bp.route('/matches/<int:match_id>/timeline', methods=['POST'])
@login_required
def toggle_match_timeline(match_id):
    """Toggle timeline inclusion for a match"""
    from models.rag import PatternMatch
    
    match = PatternMatch.query.get(match_id)
    if not match:
        return jsonify({'success': False, 'error': 'Match not found'}), 404
    
    match.include_in_timeline = not match.include_in_timeline
    db.session.commit()
    
    return jsonify({
        'success': True,
        'match_id': match_id,
        'include_in_timeline': match.include_in_timeline
    })


# ============================================================================
# CASE STATS
# ============================================================================

@rag_bp.route('/stats/<int:case_id>')
@login_required
def get_case_rag_stats(case_id):
    """Get RAG statistics for a case"""
    from models.rag import AttackPattern, PatternMatch, AttackCampaign
    from utils.clickhouse import get_client
    
    try:
        # Pattern stats
        pattern_count = AttackPattern.query.filter_by(enabled=True).count()
        
        # Match stats for this case
        match_count = PatternMatch.query.filter_by(case_id=case_id).count()
        
        # Campaign stats for this case
        campaign_count = AttackCampaign.query.filter_by(case_id=case_id).count()
        critical_campaigns = AttackCampaign.query.filter_by(
            case_id=case_id, 
            severity='critical'
        ).count()
        
        # Last scan (most recent match or campaign discovery)
        last_match = PatternMatch.query.filter_by(case_id=case_id).order_by(
            PatternMatch.discovered_at.desc()
        ).first()
        last_campaign = AttackCampaign.query.filter_by(case_id=case_id).order_by(
            AttackCampaign.detected_at.desc()
        ).first()
        
        last_scan = None
        if last_match:
            last_scan = last_match.discovered_at.isoformat()
        if last_campaign and (not last_scan or last_campaign.detected_at > last_match.discovered_at):
            last_scan = last_campaign.detected_at.isoformat()
        
        # Event stats from ClickHouse
        sigma_high_events = 0
        ioc_events = 0  # Would need ClickHouse column
        analyst_events = 0  # Would need ClickHouse column
        
        try:
            client = get_client()
            result = client.query(
                """SELECT count() FROM events 
                   WHERE case_id = {case_id:UInt32} 
                   AND rule_level IN ('high', 'critical')""",
                parameters={'case_id': case_id}
            )
            if result.result_rows:
                sigma_high_events = result.result_rows[0][0]
        except Exception:
            pass
        
        return jsonify({
            'success': True,
            'pattern_count': pattern_count,
            'match_count': match_count,
            'campaign_count': campaign_count,
            'critical_campaigns': critical_campaigns,
            'last_scan': last_scan,
            'sigma_high_events': sigma_high_events,
            'ioc_events': ioc_events,
            'analyst_events': analyst_events
        })
        
    except Exception as e:
        logger.error(f"[RAG API] Error getting stats: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# OPENCTI SYNC
# ============================================================================

@rag_bp.route('/opencti/sync', methods=['POST'])
@login_required
def sync_opencti():
    """Start OpenCTI pattern sync"""
    from tasks.rag_tasks import rag_sync_opencti_patterns
    from models.system_settings import SystemSettings, SettingKeys
    
    # Check if enabled
    opencti_enabled = SystemSettings.get(SettingKeys.OPENCTI_ENABLED, False)
    rag_sync_enabled = SystemSettings.get(SettingKeys.OPENCTI_RAG_SYNC, False)
    
    if not opencti_enabled or not rag_sync_enabled:
        return jsonify({
            'success': False,
            'error': 'OpenCTI RAG sync is disabled in settings'
        }), 400
    
    task = rag_sync_opencti_patterns.delay(triggered_by=current_user.username)
    
    return jsonify({
        'success': True,
        'task_id': task.id
    })


@rag_bp.route('/opencti/stats')
@login_required
def get_opencti_stats():
    """Get OpenCTI sync statistics"""
    from models.rag import RAGSyncLog, AttackPattern
    
    # Get last sync
    last_sync = RAGSyncLog.query.filter_by(
        source='opencti',
        success=True
    ).order_by(RAGSyncLog.completed_at.desc()).first()
    
    # Count patterns by source
    opencti_patterns = AttackPattern.query.filter_by(source='opencti').count()
    opencti_sigma = AttackPattern.query.filter_by(source='opencti_sigma').count()
    
    return jsonify({
        'success': True,
        'last_sync': last_sync.to_dict() if last_sync else None,
        'opencti_patterns': opencti_patterns,
        'opencti_indicators': opencti_sigma
    })


# ============================================================================
# HEALTH CHECK
# ============================================================================

@rag_bp.route('/health')
@login_required
def rag_health():
    """Check RAG system health"""
    from utils.rag_embeddings import health_check as embed_health
    from utils.rag_vectorstore import health_check as qdrant_health
    from utils.rag_llm import health_check as llm_health
    
    return jsonify({
        'success': True,
        'embeddings': embed_health(),
        'vectorstore': qdrant_health(),
        'llm': llm_health()
    })


@rag_bp.route('/settings')
@login_required
def get_rag_settings():
    """Get RAG-related settings for UI state"""
    from models.system_settings import SystemSettings, SettingKeys
    
    return jsonify({
        'success': True,
        'ai_enabled': SystemSettings.get(SettingKeys.AI_ENABLED, False),
        'opencti_enabled': SystemSettings.get(SettingKeys.OPENCTI_ENABLED, False),
        'opencti_rag_sync': SystemSettings.get(SettingKeys.OPENCTI_RAG_SYNC, False)
    })


# ============================================================================
# INITIALIZATION
# ============================================================================

@rag_bp.route('/init', methods=['POST'])
@login_required
def init_rag():
    """Initialize RAG system (seed patterns, create collections)"""
    from tasks.rag_tasks import rag_seed_builtin_patterns
    from utils.rag_vectorstore import init_collections
    
    try:
        # Initialize vector collections
        init_collections()
        
        # Seed builtin patterns
        task = rag_seed_builtin_patterns.delay()
        
        return jsonify({
            'success': True,
            'message': 'RAG initialization started',
            'task_id': task.id
        })
        
    except Exception as e:
        logger.error(f"[RAG API] Init error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
