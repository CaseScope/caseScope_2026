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

from config import Config
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
    total_event_count = 0
    for match in matches:
        host = match.source_host or 'Unknown'
        if host not in host_breakdown:
            host_breakdown[host] = {
                'match_records': 0,  # Number of PatternMatch records
                'event_count': 0,     # Actual matched events
                'first_seen': None,
                'last_seen': None,
                'users': set()
            }
        host_breakdown[host]['match_records'] += 1
        # Use matched_event_count if available, otherwise count as 1
        event_count = match.matched_event_count or 1
        host_breakdown[host]['event_count'] += event_count
        total_event_count += event_count
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
    for host, data in sorted(host_breakdown.items(), key=lambda x: x[1]['event_count'], reverse=True):
        host_list.append({
            'host': host,
            'count': data['event_count'],  # Show event count, not record count
            'match_records': data['match_records'],
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
        'total_events': total_event_count,
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


# ============================================================================
# NON-AI PATTERN MATCHING
# ============================================================================

@rag_bp.route('/pattern-rules/detect', methods=['POST'])
@login_required
def detect_pattern_rules():
    """Start non-AI pattern rule detection task for a case"""
    from tasks.rag_tasks import detect_attack_patterns
    from utils.timezone import to_utc
    from utils.clickhouse import get_client
    from datetime import timedelta
    
    data = request.json or {}
    case_id = data.get('case_id')
    categories = data.get('categories')  # Optional: filter by category
    time_range = data.get('time_range', 'none')  # Time range filter
    time_start = data.get('time_start', '')  # Custom start (datetime-local format)
    time_end = data.get('time_end', '')  # Custom end (datetime-local format)
    
    if not case_id:
        return jsonify({'success': False, 'error': 'case_id required'}), 400
    
    case = Case.query.get(case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    # Build time filter SQL clause
    time_filter = None
    case_tz = case.timezone or 'UTC'
    
    if time_range and time_range != 'none':
        try:
            if time_range in ('1d', '3d', '7d', '30d'):
                # Predefined ranges: relative to most recent artifact
                client = get_client()
                max_ts_query = "SELECT max(timestamp_utc) FROM events WHERE case_id = {case_id:UInt32}"
                max_ts_result = client.query(max_ts_query, parameters={'case_id': case_id})
                max_timestamp = max_ts_result.result_rows[0][0] if max_ts_result.result_rows and max_ts_result.result_rows[0][0] else None
                
                if max_timestamp:
                    days_map = {'1d': 1, '3d': 3, '7d': 7, '30d': 30}
                    days = days_map.get(time_range, 1)
                    start_utc = max_timestamp - timedelta(days=days)
                    time_filter = f"timestamp_utc >= '{start_utc.strftime('%Y-%m-%d %H:%M:%S')}'"
                    logger.info(f"Pattern detection time filter: {time_range} -> {time_filter}")
            
            elif time_range == 'custom' and time_start and time_end:
                # Custom range: convert from case timezone to UTC
                start_local = datetime.strptime(time_start, '%Y-%m-%dT%H:%M')
                end_local = datetime.strptime(time_end, '%Y-%m-%dT%H:%M')
                start_utc = to_utc(start_local, case_tz)
                end_utc = to_utc(end_local, case_tz)
                time_filter = f"timestamp_utc >= '{start_utc.strftime('%Y-%m-%d %H:%M:%S')}' AND timestamp_utc <= '{end_utc.strftime('%Y-%m-%d %H:%M:%S')}'"
                logger.info(f"Pattern detection custom time filter: {time_start} to {time_end} ({case_tz}) -> UTC: {time_filter}")
        
        except Exception as e:
            logger.warning(f"Error building time filter for pattern detection: {e}")
    
    task = detect_attack_patterns.delay(
        case_id=case_id,
        case_uuid=case.uuid,
        categories=categories,
        time_filter=time_filter
    )
    
    return jsonify({
        'success': True,
        'task_id': task.id,
        'case_id': case_id
    })


@rag_bp.route('/pattern-rules/results/<int:case_id>')
@login_required
def get_pattern_rule_results(case_id):
    """Get non-AI pattern matching results for a case"""
    from models.rag import PatternRuleMatch
    
    # Get aggregated results by pattern
    results = db.session.query(
        PatternRuleMatch.pattern_id,
        PatternRuleMatch.pattern_name,
        PatternRuleMatch.category,
        PatternRuleMatch.severity,
        PatternRuleMatch.mitre_techniques,
        db.func.count(PatternRuleMatch.id).label('match_count'),
        db.func.count(db.distinct(PatternRuleMatch.source_host)).label('host_count'),
        db.func.min(PatternRuleMatch.first_seen).label('first_seen'),
        db.func.max(PatternRuleMatch.last_seen).label('last_seen'),
        db.func.avg(PatternRuleMatch.confidence).label('avg_confidence'),
        db.func.sum(PatternRuleMatch.event_count).label('total_events')
    ).filter(
        PatternRuleMatch.case_id == case_id
    ).group_by(
        PatternRuleMatch.pattern_id,
        PatternRuleMatch.pattern_name,
        PatternRuleMatch.category,
        PatternRuleMatch.severity,
        PatternRuleMatch.mitre_techniques
    ).order_by(
        db.case(
            (PatternRuleMatch.severity == 'critical', 1),
            (PatternRuleMatch.severity == 'high', 2),
            (PatternRuleMatch.severity == 'medium', 3),
            (PatternRuleMatch.severity == 'low', 4),
            else_=5
        ),
        db.desc('match_count')
    ).all()
    
    # Format results
    formatted = []
    for row in results:
        # Recalculate confidence based on aggregated host count
        base_confidence = int(row.avg_confidence or 50)
        
        # Boost confidence for multi-host patterns
        if row.host_count >= 5:
            confidence = min(100, base_confidence + 15)
        elif row.host_count >= 3:
            confidence = min(100, base_confidence + 10)
        elif row.host_count >= 2:
            confidence = min(100, base_confidence + 5)
        else:
            confidence = base_confidence
        
        formatted.append({
            'pattern_id': row.pattern_id,
            'pattern_name': row.pattern_name,
            'category': row.category,
            'severity': row.severity,
            'mitre_techniques': row.mitre_techniques,
            'match_count': row.match_count,
            'host_count': row.host_count,
            'total_events': row.total_events or row.match_count,
            'first_seen': row.first_seen.isoformat() if row.first_seen else None,
            'last_seen': row.last_seen.isoformat() if row.last_seen else None,
            'confidence': confidence
        })
    
    # Get total matches
    total = PatternRuleMatch.query.filter_by(case_id=case_id).count()
    
    # Get category summary
    category_summary = db.session.query(
        PatternRuleMatch.category,
        db.func.count(PatternRuleMatch.id).label('count')
    ).filter(
        PatternRuleMatch.case_id == case_id
    ).group_by(
        PatternRuleMatch.category
    ).all()
    
    return jsonify({
        'success': True,
        'total_matches': total,
        'pattern_count': len(formatted),
        'patterns': formatted,
        'categories': {row.category: row.count for row in category_summary}
    })


@rag_bp.route('/pattern-rules/details/<int:case_id>/<pattern_id>')
@login_required
def get_pattern_rule_details(case_id, pattern_id):
    """Get detailed matches for a specific pattern rule"""
    from models.rag import PatternRuleMatch
    from models.pattern_rules import ALL_PATTERN_RULES
    
    matches = PatternRuleMatch.query.filter_by(
        case_id=case_id,
        pattern_id=pattern_id
    ).order_by(PatternRuleMatch.first_seen).all()
    
    # Get pattern definition to include event_ids for filtering
    pattern_def = next((p for p in ALL_PATTERN_RULES if p['id'] == pattern_id), None)
    event_ids = []
    if pattern_def:
        # Get anchor event IDs
        if 'anchor' in pattern_def and 'event_ids' in pattern_def['anchor']:
            event_ids.extend(pattern_def['anchor']['event_ids'])
        # Get supporting indicator event IDs
        if 'supporting' in pattern_def:
            for indicator in pattern_def['supporting']:
                if 'event_ids' in indicator:
                    event_ids.extend(indicator['event_ids'])
        # Remove duplicates
        event_ids = list(set(event_ids))
    
    return jsonify({
        'success': True,
        'count': len(matches),
        'matches': [m.to_dict() for m in matches],
        'event_ids': event_ids
    })


@rag_bp.route('/pattern-rules/review/<int:match_id>', methods=['POST'])
@login_required
def review_pattern_rule_match(match_id):
    """Review a pattern rule match (analyst verdict)"""
    from models.rag import PatternRuleMatch
    
    match = PatternRuleMatch.query.get(match_id)
    if not match:
        return jsonify({'success': False, 'error': 'Match not found'}), 404
    
    data = request.json or {}
    verdict = data.get('verdict')
    notes = data.get('notes', '')
    
    if verdict not in ['confirmed', 'false_positive', 'needs_review']:
        return jsonify({'success': False, 'error': 'Invalid verdict'}), 400
    
    match.analyst_reviewed = True
    match.analyst_verdict = verdict
    match.analyst_notes = notes
    match.reviewed_by = current_user.username
    match.reviewed_at = datetime.utcnow()
    db.session.commit()
    
    return jsonify({
        'success': True,
        'match_id': match_id,
        'verdict': verdict
    })


@rag_bp.route('/pattern-rules/clear/<int:case_id>', methods=['DELETE'])
@login_required
def clear_pattern_rule_results(case_id):
    """Clear all pattern rule results for a case"""
    from models.rag import PatternRuleMatch
    
    deleted = PatternRuleMatch.query.filter_by(case_id=case_id).delete()
    db.session.commit()
    
    return jsonify({
        'success': True,
        'deleted': deleted
    })


# ============================================================================
# ASK AI - RAG-POWERED HUNTING ASSISTANT
# ============================================================================

# DFIR Expert System Prompt - Designed for zero hallucinations
DFIR_SYSTEM_PROMPT = """You are a DFIR (Digital Forensics and Incident Response) expert assistant integrated into CaseScope, an incident response platform.

CRITICAL RULES:
1. ONLY analyze and reference data that is explicitly provided to you in the context
2. NEVER fabricate, assume, or hallucinate events, timestamps, usernames, hosts, or any other data
3. If you cannot find evidence for something in the provided context, clearly state "No evidence found in the provided data"
4. Always cite specific events, timestamps, and hosts when making claims
5. Distinguish between confirmed findings (with evidence) and potential areas to investigate further
6. Use precise forensic terminology

Your role is to help analysts hunt for threats by:
- Analyzing event patterns for signs of malicious activity
- Identifying indicators of compromise (IOCs)
- Recognizing attack techniques mapped to MITRE ATT&CK
- Finding correlations between events across hosts and users
- Suggesting additional queries to investigate

When analyzing data, always:
- Reference specific event IDs, timestamps, and hosts
- Explain your reasoning step by step
- Rate your confidence level (High/Medium/Low)
- Suggest follow-up investigation steps

If asked about something not in the provided data, respond: "I don't have that information in the current context. To investigate this, you could search for [specific suggestion]."
"""


@rag_bp.route('/ask', methods=['POST'])
@login_required
def ask_ai():
    """Ask AI a hunting question with RAG context
    
    Uses RAG to retrieve relevant events/patterns from the case,
    then queries the LLM with a DFIR expert system prompt.
    Logs all queries for threshold tuning and effectiveness measurement.
    """
    import time
    from utils.rag_llm import get_ollama_client
    from utils.rag_embeddings import embed_text
    from utils.rag_vectorstore import search_similar_patterns
    from utils.clickhouse import get_client
    from models.system_settings import SystemSettings, SettingKeys
    from models.rag import RAGQueryLog
    
    data = request.json or {}
    case_id = data.get('case_id')
    question = data.get('question', '').strip()
    include_patterns = data.get('include_patterns', True)
    include_high_severity = data.get('include_high_severity', True)
    max_events = data.get('max_events', 20)  # Reduced to stay within token limits
    
    if not case_id:
        return jsonify({'success': False, 'error': 'case_id required'}), 400
    
    if not question:
        return jsonify({'success': False, 'error': 'question required'}), 400
    
    # Check if AI is enabled
    ai_enabled = SystemSettings.get(SettingKeys.AI_ENABLED, False)
    if not ai_enabled:
        return jsonify({'success': False, 'error': 'AI features are disabled in settings'}), 400
    
    case = Case.query.get(case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    # Initialize timing and logging variables
    start_time = time.time()
    embedding_duration_ms = None
    search_duration_ms = None
    pattern_scores = []
    score_threshold_used = 0.4
    query_log_id = None
    
    try:
        client = get_client()
        context_parts = []
        
        # 1. Embed the question and find relevant patterns
        pattern_context = []
        if include_patterns:
            try:
                embed_start = time.time()
                question_embedding = embed_text(question)
                embedding_duration_ms = int((time.time() - embed_start) * 1000)
                
                search_start = time.time()
                similar_patterns = search_similar_patterns(question_embedding, limit=5, score_threshold=score_threshold_used)
                search_duration_ms = int((time.time() - search_start) * 1000)
                
                for pattern in similar_patterns:
                    payload = pattern.get('payload', {})
                    score = pattern.get('score', 0)
                    pattern_scores.append(score)
                    pattern_context.append({
                        'name': payload.get('name', 'Unknown'),
                        'description': payload.get('description', ''),
                        'mitre': payload.get('mitre_technique', ''),
                        'severity': payload.get('severity', 'medium'),
                        'score': round(score, 2)
                    })
                
                if pattern_context:
                    context_parts.append("RELEVANT ATTACK PATTERNS:")
                    for p in pattern_context:
                        context_parts.append(f"  - {p['name']} (MITRE: {p['mitre']}, Severity: {p['severity']})")
                        if p['description']:
                            context_parts.append(f"    Description: {p['description'][:200]}")
            except Exception as e:
                logger.warning(f"[Ask AI] Pattern search failed: {e}")
        
        # 2. Get high-severity events if requested
        if include_high_severity:
            try:
                high_severity_query = """
                SELECT 
                    timestamp_utc, 
                    event_id, 
                    channel, 
                    source_host,
                    username,
                    rule_title,
                    rule_level,
                    process_name,
                    command_line
                FROM events 
                WHERE case_id = {case_id:UInt32} 
                AND rule_level IN ('high', 'critical')
                ORDER BY timestamp_utc DESC
                LIMIT {limit:UInt32}
                """
                result = client.query(high_severity_query, parameters={'case_id': case_id, 'limit': max_events})
                
                if result.result_rows:
                    context_parts.append(f"\nHIGH SEVERITY EVENTS ({len(result.result_rows)} events):")
                    for row in result.result_rows:
                        ts, eid, ch, comp, user, title, level, proc, cmd = row
                        event_line = f"  [{ts}] {level.upper() if level else 'INFO'}: {title or 'No title'}"
                        if comp:
                            event_line += f" | Host: {comp}"
                        if user:
                            event_line += f" | User: {user}"
                        if proc:
                            event_line += f" | Process: {proc}"
                        context_parts.append(event_line)
                        if cmd and len(cmd) < 200:
                            context_parts.append(f"    Command: {cmd}")
            except Exception as e:
                logger.warning(f"[Ask AI] High severity query failed: {e}")
        
        # 3. Run specialized queries based on question type
        question_lower = question.lower()
        search_terms = []
        
        # BRUTE FORCE / FAILED LOGINS - specialized aggregation query
        if any(kw in question_lower for kw in ['brute', 'failed login', 'failed logon', 'password spray', 'lockout']):
            try:
                # Get failed login summary by user
                failed_login_query = """
                SELECT 
                    username,
                    source_host,
                    count() as fail_count,
                    min(timestamp_utc) as first_fail,
                    max(timestamp_utc) as last_fail,
                    groupUniqArray(10)(toString(src_ip)) as source_ips
                FROM events 
                WHERE case_id = {case_id:UInt32} 
                AND event_id IN ('4625', '4771', '529', '530', '531', '532', '533', '534', '535', '536', '537', '539')
                GROUP BY username, source_host
                ORDER BY fail_count DESC
                LIMIT 30
                """
                result = client.query(failed_login_query, parameters={'case_id': case_id})
                
                if result.result_rows:
                    total_failures = sum(row[2] for row in result.result_rows)
                    context_parts.append(f"\nFAILED LOGIN ANALYSIS ({total_failures} total failures):")
                    context_parts.append("  User | Host | Failures | First | Last | Source IPs")
                    context_parts.append("  " + "-" * 80)
                    for row in result.result_rows:
                        user, host, count, first, last, ips = row
                        ip_list = ', '.join(str(ip) for ip in ips[:3] if ip) if ips else 'N/A'
                        context_parts.append(f"  {user or 'Unknown'} | {host or 'Unknown'} | {count} | {first} | {last} | {ip_list}")
                    
                    # Flag potential brute force (many failures in short time)
                    for row in result.result_rows:
                        if row[2] >= 5:  # 5+ failures
                            context_parts.append(f"\n  ⚠️ POTENTIAL BRUTE FORCE: {row[0]} has {row[2]} failures on {row[1]}")
                else:
                    context_parts.append("\nFAILED LOGIN ANALYSIS: No failed login events (4625, 4771) found in case data.")
                    
                search_terms.extend(['4625', '4771', 'failed'])
            except Exception as e:
                logger.warning(f"[Ask AI] Failed login query error: {e}")
        
        # PASS THE HASH - look for NTLM logons
        elif any(kw in question_lower for kw in ['pass the hash', 'pth', 'ntlm']):
            try:
                pth_query = """
                SELECT 
                    username,
                    source_host,
                    toString(src_ip) as src_ip_str,
                    logon_type,
                    auth_package,
                    count() as logon_count,
                    min(timestamp_utc) as first_seen,
                    max(timestamp_utc) as last_seen
                FROM events 
                WHERE case_id = {case_id:UInt32} 
                AND event_id = '4624'
                AND (auth_package = 'NTLM' OR logon_type IN (3, 9))
                GROUP BY username, source_host, src_ip, logon_type, auth_package
                ORDER BY logon_count DESC
                LIMIT 30
                """
                result = client.query(pth_query, parameters={'case_id': case_id})
                
                if result.result_rows:
                    context_parts.append(f"\nNTLM/NETWORK LOGON ANALYSIS ({len(result.result_rows)} user-host combinations):")
                    for row in result.result_rows:
                        user, host, src_ip, logon_type, auth_pkg, count, first, last = row
                        context_parts.append(f"  {user} -> {host} from {src_ip or 'local'} | Type:{logon_type} Auth:{auth_pkg} | {count}x ({first})")
                else:
                    context_parts.append("\nNTLM LOGON ANALYSIS: No NTLM network logons (4624 Type 3/9) found.")
                    
                search_terms.extend(['4624', 'ntlm'])
            except Exception as e:
                logger.warning(f"[Ask AI] PTH query error: {e}")
        
        # LATERAL MOVEMENT - RDP, SMB, remote logons
        elif any(kw in question_lower for kw in ['lateral', 'movement', 'rdp', 'remote', 'smb']):
            try:
                lateral_query = """
                SELECT 
                    username,
                    source_host,
                    toString(src_ip) as src_ip_str,
                    event_id,
                    logon_type,
                    count() as logon_count,
                    min(timestamp_utc) as first_seen,
                    max(timestamp_utc) as last_seen
                FROM events 
                WHERE case_id = {case_id:UInt32} 
                AND event_id IN ('4624', '4625', '4648')
                AND src_ip IS NOT NULL
                GROUP BY username, source_host, src_ip, event_id, logon_type
                ORDER BY logon_count DESC
                LIMIT 40
                """
                result = client.query(lateral_query, parameters={'case_id': case_id})
                
                if result.result_rows:
                    context_parts.append(f"\nREMOTE/LATERAL LOGON ANALYSIS:")
                    for row in result.result_rows:
                        user, host, src_ip, eid, logon_type, count, first, last = row
                        status = "SUCCESS" if eid == '4624' else "FAILED" if eid == '4625' else "EXPLICIT"
                        context_parts.append(f"  [{status}] {user} -> {host} from {src_ip} | Type:{logon_type} | {count}x ({first})")
                else:
                    context_parts.append("\nLATERAL MOVEMENT ANALYSIS: No remote logon events with source IPs found.")
                    
                search_terms.extend(['4624', '4625', 'remote'])
            except Exception as e:
                logger.warning(f"[Ask AI] Lateral movement query error: {e}")
        
        # POWERSHELL activity
        elif 'powershell' in question_lower:
            try:
                ps_query = """
                SELECT 
                    timestamp_utc,
                    source_host,
                    username,
                    rule_title,
                    substring(command_line, 1, 300) as cmd_preview
                FROM events 
                WHERE case_id = {case_id:UInt32} 
                AND (event_id IN ('4103', '4104', '400', '403', '600') OR lower(process_name) LIKE '%powershell%')
                ORDER BY timestamp_utc DESC
                LIMIT 50
                """
                result = client.query(ps_query, parameters={'case_id': case_id})
                
                if result.result_rows:
                    context_parts.append(f"\nPOWERSHELL ACTIVITY ({len(result.result_rows)} events):")
                    for row in result.result_rows:
                        ts, host, user, title, cmd = row
                        context_parts.append(f"  [{ts}] {host} | {user} | {title or 'PowerShell'}")
                        if cmd:
                            context_parts.append(f"    > {cmd[:200]}")
                else:
                    context_parts.append("\nPOWERSHELL ANALYSIS: No PowerShell events found.")
                    
                search_terms.extend(['4103', '4104', 'powershell'])
            except Exception as e:
                logger.warning(f"[Ask AI] PowerShell query error: {e}")
        
        # Generic keyword search for other questions
        else:
            dfir_keywords = {
                'privilege': ['4672', '4673', 'privilege', 'admin'],
                'credential': ['credential', 'lsass', 'password', 'mimikatz', 'sekurlsa'],
                'persistence': ['registry', 'scheduled', 'service', 'run key', 'startup'],
                'exfil': ['upload', 'transfer', 'compress', 'archive'],
                'kerberos': ['4768', '4769', '4770', 'kerberos', 'ticket'],
            }
            
            for keyword, terms in dfir_keywords.items():
                if keyword in question_lower:
                    search_terms.extend(terms)
        
        # 4. If we have search terms, query for sample events
        if search_terms:
            try:
                # Sanitize and deduplicate search terms
                safe_terms = []
                event_id_terms = []
                
                for term in list(set(search_terms))[:6]:  # Dedupe and limit
                    # Sanitize: only allow alphanumeric, spaces, underscores, hyphens
                    import re
                    sanitized = re.sub(r'[^\w\s\-]', '', str(term))
                    if not sanitized:
                        continue
                    
                    if sanitized.isdigit():
                        event_id_terms.append(sanitized)
                    else:
                        safe_terms.append(sanitized.lower())
                
                # Build safe parameterized conditions
                conditions = []
                
                # Event ID matching (using IN clause with sanitized values)
                if event_id_terms:
                    event_ids_str = "', '".join(event_id_terms)
                    conditions.append(f"event_id IN ('{event_ids_str}')")
                
                # Text matching using hasTokenCaseInsensitive (safer than LIKE with user input)
                # This is ClickHouse's full-text search that doesn't require escaping
                for term in safe_terms[:4]:  # Limit text terms
                    # Use multiSearchAnyCaseInsensitive for safe substring matching
                    conditions.append(
                        f"(positionCaseInsensitive(rule_title, '{term}') > 0 OR "
                        f"positionCaseInsensitive(command_line, '{term}') > 0 OR "
                        f"positionCaseInsensitive(channel, '{term}') > 0)"
                    )
                
                if not conditions:
                    conditions = ["1=1"]  # No valid terms, will return nothing meaningful
                
                search_query = f"""
                SELECT 
                    timestamp_utc, 
                    event_id, 
                    channel, 
                    source_host,
                    username,
                    toString(src_ip) as src_ip_str,
                    rule_title,
                    rule_level,
                    process_name,
                    substring(command_line, 1, 200) as cmd
                FROM events 
                WHERE case_id = {{case_id:UInt32}} 
                AND ({' OR '.join(conditions)})
                ORDER BY timestamp_utc DESC
                LIMIT {{limit:UInt32}}
                """
                result = client.query(search_query, parameters={'case_id': case_id, 'limit': max_events})
                
                if result.result_rows:
                    context_parts.append(f"\nSAMPLE MATCHING EVENTS ({len(result.result_rows)} events):")
                    for row in result.result_rows[:30]:
                        ts, eid, ch, comp, user, src_ip, title, level, proc, cmd = row
                        event_line = f"  [{ts}] EventID:{eid}"
                        if title:
                            event_line += f" {title}"
                        if comp:
                            event_line += f" | Host: {comp}"
                        if user:
                            event_line += f" | User: {user}"
                        if src_ip:
                            event_line += f" | Source: {src_ip}"
                        context_parts.append(event_line)
            except Exception as e:
                logger.warning(f"[Ask AI] Related events query failed: {e}")
        
        # 5. Get case summary stats
        try:
            stats_query = """
            SELECT 
                count() as total,
                countIf(rule_level = 'critical') as critical,
                countIf(rule_level = 'high') as high,
                countIf(rule_level = 'medium') as medium,
                min(timestamp_utc) as first_event,
                max(timestamp_utc) as last_event,
                count(DISTINCT source_host) as hosts,
                count(DISTINCT username) as users
            FROM events 
            WHERE case_id = {case_id:UInt32}
            """
            result = client.query(stats_query, parameters={'case_id': case_id})
            
            if result.result_rows:
                row = result.result_rows[0]
                context_parts.insert(0, f"CASE SUMMARY:")
                context_parts.insert(1, f"  Case: {case.name}")
                context_parts.insert(2, f"  Total Events: {row[0]:,}")
                context_parts.insert(3, f"  Critical: {row[1]}, High: {row[2]}, Medium: {row[3]}")
                context_parts.insert(4, f"  Timeframe: {row[4]} to {row[5]}")
                context_parts.insert(5, f"  Unique Hosts: {row[6]}, Unique Users: {row[7]}")
                context_parts.insert(6, "")
        except Exception as e:
            logger.warning(f"[Ask AI] Stats query failed: {e}")
        
        # 6. Add pattern match results if available (Priority 3.2)
        try:
            from models.rag import PatternRuleMatch
            
            pattern_matches = PatternRuleMatch.query.filter_by(case_id=case_id).order_by(
                PatternRuleMatch.confidence.desc()
            ).limit(10).all()
            
            if pattern_matches:
                context_parts.append(f"\nDETECTED ATTACK PATTERNS ({len(pattern_matches)} top matches):")
                for pm in pattern_matches:
                    match_line = f"  [{pm.severity.upper()}] {pm.pattern_name}"
                    if pm.source_host:
                        match_line += f" | Host: {pm.source_host}"
                    if pm.username:
                        match_line += f" | User: {pm.username}"
                    match_line += f" | Confidence: {pm.confidence}%"
                    if pm.mitre_techniques:
                        match_line += f" | MITRE: {', '.join(pm.mitre_techniques[:2])}"
                    context_parts.append(match_line)
        except Exception as e:
            logger.debug(f"[Ask AI] Could not load pattern matches: {e}")
        
        # Build the full prompt - use centralized config for max context
        context_text = "\n".join(context_parts) if context_parts else "No relevant data found in the case."
        max_context_chars = getattr(Config, 'RAG_MAX_CONTEXT_CHARS', 12000)
        if len(context_text) > max_context_chars:
            # Prioritize: case summary, pattern matches, high-severity events, then samples
            context_text = context_text[:max_context_chars] + "\n... [Context truncated for token limit]"
        
        user_prompt = f"""Based on the following data from the investigation, please answer this question:

QUESTION: {question}

{context_text}

Provide a detailed analysis based ONLY on the data above. If you cannot find evidence for something, say so clearly."""

        # Query the LLM
        ollama_client = get_ollama_client()
        result = ollama_client.generate(
            prompt=user_prompt,
            system=DFIR_SYSTEM_PROMPT,
            temperature=0.3,  # Lower temperature for more factual responses
            max_tokens=2000
        )
        
        if not result.get('success'):
            return jsonify({
                'success': False,
                'error': result.get('error', 'LLM query failed')
            }), 500
        
        # Calculate total duration
        total_duration_ms = int((time.time() - start_time) * 1000)
        
        # Log query for baseline establishment and threshold tuning
        try:
            query_log = RAGQueryLog(
                case_id=case_id,
                query_text=question,
                query_type='ask_ai',
                patterns_returned=len(pattern_context),
                top_score=max(pattern_scores) if pattern_scores else None,
                avg_score=sum(pattern_scores) / len(pattern_scores) if pattern_scores else None,
                min_score=min(pattern_scores) if pattern_scores else None,
                score_threshold_used=score_threshold_used,
                embedding_duration_ms=embedding_duration_ms,
                search_duration_ms=search_duration_ms,
                total_duration_ms=total_duration_ms,
                llm_model=result.get('model'),
                user_id=current_user.username if current_user else None
            )
            db.session.add(query_log)
            db.session.commit()
            query_log_id = query_log.id
        except Exception as log_err:
            logger.warning(f"[Ask AI] Failed to log query: {log_err}")
            db.session.rollback()
        
        # Save to server-side history for cross-device persistence
        history_id = None
        try:
            from models.rag import AskAIHistory
            
            history_entry = AskAIHistory(
                case_id=case_id,
                user_id=current_user.username if current_user else 'anonymous',
                question=question,
                answer=result.get('response', ''),
                patterns_found=len(pattern_context),
                events_analyzed=len([p for p in context_parts if p.startswith('  [')]),
                search_terms_used=search_terms[:5] if search_terms else None,
                duration_ms=total_duration_ms,
                model_used=result.get('model')
            )
            db.session.add(history_entry)
            db.session.commit()
            history_id = history_entry.id
        except Exception as hist_err:
            logger.warning(f"[Ask AI] Failed to save history: {hist_err}")
            db.session.rollback()
        
        return jsonify({
            'success': True,
            'answer': result.get('response', ''),
            'context_summary': {
                'patterns_found': len(pattern_context),
                'events_analyzed': len([p for p in context_parts if p.startswith('  [')]),
                'search_terms_used': search_terms[:5] if search_terms else []
            },
            'model': result.get('model'),
            'duration_ns': result.get('total_duration'),
            'query_log_id': query_log_id,  # For feedback submission
            'history_id': history_id  # For server-side history reference
        })
        
    except Exception as e:
        logger.error(f"[Ask AI] Error: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@rag_bp.route('/ask/feedback', methods=['POST'])
@login_required
def submit_query_feedback():
    """Submit feedback on an Ask AI query for threshold tuning
    
    This feedback helps establish baselines for score thresholds.
    """
    from models.rag import RAGQueryLog
    
    data = request.json or {}
    query_log_id = data.get('query_log_id')
    feedback = data.get('feedback')  # 'helpful' or 'not_helpful'
    notes = data.get('notes', '')
    
    if not query_log_id:
        return jsonify({'success': False, 'error': 'query_log_id required'}), 400
    
    if feedback not in ('helpful', 'not_helpful'):
        return jsonify({'success': False, 'error': 'feedback must be "helpful" or "not_helpful"'}), 400
    
    try:
        query_log = RAGQueryLog.query.get(query_log_id)
        if not query_log:
            return jsonify({'success': False, 'error': 'Query log not found'}), 404
        
        query_log.user_feedback = feedback
        query_log.feedback_notes = notes
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Feedback recorded',
            'query_log_id': query_log_id
        })
        
    except Exception as e:
        logger.error(f"[Ask AI Feedback] Error: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@rag_bp.route('/semantic-feedback', methods=['POST'])
@login_required
def submit_semantic_feedback():
    """Submit analyst feedback on a semantic match for threshold tuning
    
    When an analyst confirms or rejects a semantic match, this data
    informs per-pattern threshold adjustments.
    """
    from models.rag import SemanticMatchFeedback
    
    data = request.json or {}
    case_id = data.get('case_id')
    pattern_id = data.get('pattern_id')
    similarity_score = data.get('similarity_score')
    verdict = data.get('verdict')  # 'confirmed', 'rejected', 'uncertain'
    
    if not all([case_id, pattern_id, similarity_score, verdict]):
        return jsonify({'success': False, 'error': 'case_id, pattern_id, similarity_score, and verdict required'}), 400
    
    if verdict not in ('confirmed', 'rejected', 'uncertain'):
        return jsonify({'success': False, 'error': 'verdict must be "confirmed", "rejected", or "uncertain"'}), 400
    
    try:
        feedback = SemanticMatchFeedback(
            case_id=case_id,
            pattern_id=pattern_id,
            similarity_score=similarity_score,
            query_text=data.get('query_text'),
            matched_event_summary=data.get('matched_event_summary'),
            verdict=verdict,
            verdict_reason=data.get('verdict_reason'),
            analyst_username=current_user.username if current_user else 'unknown'
        )
        db.session.add(feedback)
        db.session.commit()
        
        # Return updated threshold recommendation
        recommendation = SemanticMatchFeedback.get_pattern_threshold_recommendation(pattern_id)
        
        return jsonify({
            'success': True,
            'message': 'Feedback recorded',
            'feedback_id': feedback.id,
            'threshold_recommendation': recommendation
        })
        
    except Exception as e:
        logger.error(f"[Semantic Feedback] Error: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@rag_bp.route('/query-stats')
@login_required
def get_query_stats():
    """Get RAG query statistics for threshold tuning and monitoring
    
    Provides score distributions and feedback summaries.
    """
    from models.rag import RAGQueryLog
    
    try:
        query_type = request.args.get('query_type')
        
        stats = RAGQueryLog.get_score_distribution(query_type=query_type)
        
        # Get recent queries for inspection
        recent_query = RAGQueryLog.query.order_by(RAGQueryLog.created_at.desc())
        if query_type:
            recent_query = recent_query.filter_by(query_type=query_type)
        recent = recent_query.limit(10).all()
        
        return jsonify({
            'success': True,
            'stats': stats,
            'recent_queries': [q.to_dict() for q in recent]
        })
        
    except Exception as e:
        logger.error(f"[Query Stats] Error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# SERVER-SIDE ASK AI HISTORY
# ============================================================================

@rag_bp.route('/ask/history/<int:case_id>')
@login_required
def get_ask_ai_history(case_id):
    """Get server-side Ask AI history for a case
    
    Returns the user's recent Ask AI queries for this case.
    """
    from models.rag import AskAIHistory
    
    try:
        limit = request.args.get('limit', 20, type=int)
        history = AskAIHistory.get_user_history(
            case_id=case_id,
            user_id=current_user.username,
            limit=min(limit, 50)
        )
        
        return jsonify({
            'success': True,
            'count': len(history),
            'history': [h.to_dict() for h in history]
        })
        
    except Exception as e:
        logger.error(f"[Ask AI History] Error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@rag_bp.route('/ask/history', methods=['POST'])
@login_required
def save_ask_ai_history():
    """Save an Ask AI query to server-side history
    
    Called after a successful Ask AI query to persist the conversation.
    """
    from models.rag import AskAIHistory
    
    data = request.json or {}
    case_id = data.get('case_id')
    question = data.get('question')
    answer = data.get('answer')
    
    if not case_id or not question:
        return jsonify({'success': False, 'error': 'case_id and question required'}), 400
    
    try:
        history_entry = AskAIHistory(
            case_id=case_id,
            user_id=current_user.username,
            question=question,
            answer=answer,
            patterns_found=data.get('patterns_found', 0),
            events_analyzed=data.get('events_analyzed', 0),
            search_terms_used=data.get('search_terms_used'),
            duration_ms=data.get('duration_ms'),
            model_used=data.get('model_used')
        )
        db.session.add(history_entry)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'history_id': history_entry.id
        })
        
    except Exception as e:
        logger.error(f"[Ask AI History] Save error: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@rag_bp.route('/ask/history/<int:history_id>', methods=['DELETE'])
@login_required
def delete_ask_ai_history(history_id):
    """Delete a specific Ask AI history entry"""
    from models.rag import AskAIHistory
    
    try:
        entry = AskAIHistory.query.get(history_id)
        if not entry:
            return jsonify({'success': False, 'error': 'Entry not found'}), 404
        
        # Only allow deleting own history
        if entry.user_id != current_user.username:
            return jsonify({'success': False, 'error': 'Not authorized'}), 403
        
        db.session.delete(entry)
        db.session.commit()
        
        return jsonify({'success': True})
        
    except Exception as e:
        logger.error(f"[Ask AI History] Delete error: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# FEEDBACK-DRIVEN THRESHOLD TUNING
# ============================================================================

@rag_bp.route('/thresholds/recommendations')
@login_required
def get_threshold_recommendations():
    """Get threshold recommendations based on analyst feedback
    
    Analyzes SemanticMatchFeedback data to recommend optimal thresholds
    for each pattern and globally.
    """
    from models.rag import SemanticMatchFeedback, AttackPattern
    from sqlalchemy import func
    
    try:
        # Get patterns with feedback
        patterns_with_feedback = db.session.query(
            SemanticMatchFeedback.pattern_id,
            func.count(SemanticMatchFeedback.id).label('feedback_count')
        ).group_by(SemanticMatchFeedback.pattern_id).having(
            func.count(SemanticMatchFeedback.id) >= 3  # Minimum feedback for recommendation
        ).all()
        
        recommendations = []
        for pattern_id, feedback_count in patterns_with_feedback:
            rec = SemanticMatchFeedback.get_pattern_threshold_recommendation(pattern_id)
            if rec['recommended_threshold']:
                pattern = AttackPattern.query.get(pattern_id)
                recommendations.append({
                    'pattern_id': pattern_id,
                    'pattern_name': pattern.name if pattern else 'Unknown',
                    'current_threshold': pattern.semantic_threshold if pattern else None,
                    'recommended_threshold': rec['recommended_threshold'],
                    'avg_confirmed_score': rec['avg_confirmed_score'],
                    'avg_rejected_score': rec['avg_rejected_score'],
                    'feedback_count': feedback_count
                })
        
        # Global recommendation based on all feedback
        global_confirmed = db.session.query(
            func.avg(SemanticMatchFeedback.similarity_score)
        ).filter(SemanticMatchFeedback.verdict == 'confirmed').scalar()
        
        global_rejected = db.session.query(
            func.avg(SemanticMatchFeedback.similarity_score)
        ).filter(SemanticMatchFeedback.verdict == 'rejected').scalar()
        
        global_recommendation = None
        if global_confirmed and global_rejected:
            global_recommendation = (global_confirmed + global_rejected) / 2
        elif global_confirmed:
            global_recommendation = global_confirmed * 0.9
        
        return jsonify({
            'success': True,
            'global_recommendation': float(global_recommendation) if global_recommendation else None,
            'global_confirmed_avg': float(global_confirmed) if global_confirmed else None,
            'global_rejected_avg': float(global_rejected) if global_rejected else None,
            'pattern_recommendations': recommendations
        })
        
    except Exception as e:
        logger.error(f"[Threshold Recommendations] Error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@rag_bp.route('/thresholds/apply', methods=['POST'])
@login_required
def apply_threshold_recommendations():
    """Apply recommended thresholds to patterns
    
    Updates semantic_threshold for specified patterns based on feedback.
    """
    from models.rag import AttackPattern
    
    data = request.json or {}
    pattern_thresholds = data.get('pattern_thresholds', {})  # {pattern_id: threshold}
    
    if not pattern_thresholds:
        return jsonify({'success': False, 'error': 'No thresholds provided'}), 400
    
    try:
        updated = 0
        for pattern_id, threshold in pattern_thresholds.items():
            pattern = AttackPattern.query.get(int(pattern_id))
            if pattern:
                pattern.semantic_threshold = float(threshold)
                updated += 1
        
        db.session.commit()
        
        logger.info(f"[Threshold Apply] Updated {updated} pattern thresholds by {current_user.username}")
        
        return jsonify({
            'success': True,
            'updated': updated
        })
        
    except Exception as e:
        logger.error(f"[Threshold Apply] Error: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# HIGH-SEVERITY EVENT EMBEDDING
# ============================================================================

@rag_bp.route('/events/embed/<int:case_id>', methods=['POST'])
@login_required
def embed_case_events(case_id):
    """Trigger embedding of high-severity events for a case
    
    Embeds critical/high severity events into a Qdrant collection
    for semantic search during investigation.
    """
    from models.case import Case
    from tasks.rag_tasks import rag_embed_high_severity_events
    
    case = Case.query.get(case_id)
    if not case:
        return jsonify({'success': False, 'error': 'Case not found'}), 404
    
    data = request.json or {}
    max_events = min(data.get('max_events', 5000), 10000)
    
    try:
        task = rag_embed_high_severity_events.delay(
            case_id=case_id,
            case_uuid=str(case.uuid),
            max_events=max_events
        )
        
        return jsonify({
            'success': True,
            'task_id': task.id,
            'message': f'Started event embedding for case {case_id}'
        })
        
    except Exception as e:
        logger.error(f"[Event Embedding] Error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@rag_bp.route('/events/search/<int:case_id>', methods=['POST'])
@login_required
def search_embedded_events(case_id):
    """Search embedded events using semantic similarity
    
    Searches the case's event embedding collection for events
    semantically similar to the query.
    """
    from utils.rag_embeddings import embed_text
    from utils.rag_vectorstore import get_qdrant_client
    from config import Config
    
    data = request.json or {}
    query = data.get('query')
    limit = min(data.get('limit', 20), 100)
    threshold = data.get('threshold', getattr(Config, 'RAG_SEMANTIC_THRESHOLD', 0.45))
    
    if not query:
        return jsonify({'success': False, 'error': 'Query is required'}), 400
    
    try:
        # Embed the query
        query_embedding = embed_text(query)
        
        # Search in case-specific collection
        collection_name = f"case_{case_id}_events"
        qdrant_client = get_qdrant_client()
        
        # Check if collection exists
        collections = qdrant_client.get_collections().collections
        if not any(c.name == collection_name for c in collections):
            return jsonify({
                'success': False,
                'error': 'Event embeddings not found for this case. Run embedding first.'
            }), 404
        
        # Search
        results = qdrant_client.search(
            collection_name=collection_name,
            query_vector=query_embedding,
            limit=limit,
            score_threshold=threshold
        )
        
        events = []
        for result in results:
            event = result.payload.copy()
            event['similarity_score'] = round(result.score, 3)
            events.append(event)
        
        return jsonify({
            'success': True,
            'query': query,
            'count': len(events),
            'events': events
        })
        
    except Exception as e:
        logger.error(f"[Event Search] Error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@rag_bp.route('/events/embedding-status/<int:case_id>')
@login_required
def get_event_embedding_status(case_id):
    """Get the status of event embeddings for a case"""
    from utils.rag_vectorstore import get_qdrant_client
    
    try:
        collection_name = f"case_{case_id}_events"
        qdrant_client = get_qdrant_client()
        
        # Check if collection exists
        collections = qdrant_client.get_collections().collections
        collection = next((c for c in collections if c.name == collection_name), None)
        
        if not collection:
            return jsonify({
                'success': True,
                'embedded': False,
                'message': 'No event embeddings found for this case'
            })
        
        # Get collection info
        info = qdrant_client.get_collection(collection_name)
        
        return jsonify({
            'success': True,
            'embedded': True,
            'collection_name': collection_name,
            'vectors_count': info.vectors_count,
            'points_count': info.points_count
        })
        
    except Exception as e:
        logger.error(f"[Embedding Status] Error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
