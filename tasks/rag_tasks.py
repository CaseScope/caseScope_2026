"""RAG Tasks for CaseScope - Pattern Discovery and Timeline Generation

Provides Celery tasks for:
- Pattern discovery across case events
- Related event hunting
- Timeline generation
- OpenCTI pattern sync
"""

import hashlib
import logging
import re
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple

from tasks.celery_tasks import celery_app, get_flask_app
from utils.finding_contract import (
    build_deterministic_analysis_artifacts,
    finalize_deterministic_package,
    severity_from_confidence,
)
from utils.attack_pattern_loader import (
    OPENCTI_ATTACK_PATTERN_UPDATE_FIELDS,
    SYNC_ATTACK_PATTERN_UPDATE_FIELDS,
    apply_pattern_sync_result,
    build_attack_pattern_payload,
    normalize_mitre_attack_pattern,
    normalize_opencti_attack_pattern,
    normalize_opencti_sigma_indicator,
    persist_attack_pattern_payload,
    resolve_attack_pattern_lookup,
    save_synced_attack_pattern,
)
from utils.hunting_logger import HuntingLogger, get_hunting_logger
from utils.pattern_sync_execution import (
    build_external_sync_source_stage_runners,
    run_pattern_vector_update_stage,
)
from utils.pattern_sync_reporting import (
    get_default_external_sync_sources,
    initialize_external_sync_stats,
    apply_external_source_sync_result,
    run_external_sync_stage,
    build_mitre_sync_response,
    build_multi_source_sync_response,
    build_opencti_sync_response,
    finalize_rag_sync_log,
    summarize_sync_errors,
)
from utils.pattern_suppression import (
    PATTERN_SUPPRESSION_PRIORITY,
    build_confirmed_pattern_entry,
    should_track_pattern_for_suppression,
)

logger = logging.getLogger(__name__)

EVENT_EMBED_LOCK_TTL_SECONDS = 15 * 60

SUPPORTED_TIME_FILTER_RE = re.compile(
    r"^COALESCE\(timestamp_utc, timestamp\) >= '\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}'"
    r"(?: AND COALESCE\(timestamp_utc, timestamp\) <= '\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}')?$"
)


def _build_time_filter_clause(time_filter: Optional[str]) -> str:
    """Validate and return a supported time-filter clause."""
    if not time_filter:
        return ""
    if not SUPPORTED_TIME_FILTER_RE.fullmatch(time_filter.strip()):
        raise ValueError("Unsupported time filter format")
    return f" AND {time_filter.strip()}"


def _get_high_priority_rule_levels() -> Tuple[str, ...]:
    """Return normalized Hayabusa/Sigma severities treated as high signal."""
    return ('crit', 'critical', 'high')


def _build_case_event_collection_name(case_id: int) -> str:
    """Return the Qdrant collection name for case event vectors."""
    return f"case_{case_id}_events"


def _build_event_embedding_conditions(
    scope: str,
    *,
    time_start: Optional[str] = None,
    time_end: Optional[str] = None,
) -> Tuple[List[str], Dict[str, Any]]:
    """Build ClickHouse filter conditions for event embedding scopes."""
    conditions = []
    parameters: Dict[str, Any] = {}

    if scope == 'analyst_tagged':
        conditions.append("analyst_tagged = true")
    elif scope == 'ioc_tagged':
        conditions.append("length(ioc_types) > 0")
    elif scope == 'time_range':
        conditions.append("timestamp_utc >= parseDateTimeBestEffort({time_start:String})")
        conditions.append("timestamp_utc <= parseDateTimeBestEffort({time_end:String})")
        parameters['time_start'] = time_start
        parameters['time_end'] = time_end
    else:
        quoted_levels = ", ".join(f"'{level}'" for level in _get_high_priority_rule_levels())
        conditions.append(f"rule_level IN ({quoted_levels})")

    return conditions, parameters


def _build_event_vector_point_id(case_id: int, scope: str, record_id: Any) -> int:
    """Create a deterministic numeric Qdrant point ID per case, scope, and event."""
    raw = f"{case_id}:{scope}:{record_id}".encode('utf-8')
    digest = hashlib.sha1(raw).digest()
    return int.from_bytes(digest[:8], 'big') & ((1 << 63) - 1)


def _get_event_embedding_lock_key(case_id: int, scope: str) -> str:
    """Redis key for per-case, per-scope event embedding serialization."""
    return f"rag:event_embedding_lock:{case_id}:{scope}"


def _get_rag_redis_client():
    """Create a Redis client for lightweight RAG task coordination."""
    import redis
    from config import Config

    return redis.Redis(
        host=Config.REDIS_HOST,
        port=Config.REDIS_PORT,
        db=Config.REDIS_DB,
        decode_responses=True,
    )


def _acquire_event_embedding_lock(case_id: int, scope: str, owner: str) -> bool:
    """Acquire a best-effort Redis lock to prevent overlapping scope refreshes."""
    try:
        client = _get_rag_redis_client()
        return bool(client.set(
            _get_event_embedding_lock_key(case_id, scope),
            owner,
            nx=True,
            ex=EVENT_EMBED_LOCK_TTL_SECONDS,
        ))
    except Exception as exc:
        logger.warning(f"[RAG Events] Failed to acquire embed lock for case {case_id} scope {scope}: {exc}")
        return True


def _release_event_embedding_lock(case_id: int, scope: str, owner: str) -> None:
    """Release the Redis lock only if this task still owns it."""
    try:
        client = _get_rag_redis_client()
        key = _get_event_embedding_lock_key(case_id, scope)
        if client.get(key) == owner:
            client.delete(key)
    except Exception as exc:
        logger.warning(f"[RAG Events] Failed to release embed lock for case {case_id} scope {scope}: {exc}")


def _delete_scope_event_vectors(qdrant_client, collection_name: str, scope: str) -> bool:
    """Delete all event vectors for a specific embedding scope within a case collection."""
    from qdrant_client.models import Filter, FieldCondition, MatchValue

    collections = qdrant_client.get_collections().collections
    if not any(collection.name == collection_name for collection in collections):
        return False

    qdrant_client.delete(
        collection_name=collection_name,
        points_selector=Filter(
            must=[
                FieldCondition(
                    key='embedding_scope',
                    match=MatchValue(value=scope),
                )
            ]
        ),
        wait=True,
    )
    return True


# =============================================================================
# CASE ANALYSIS TASK
# =============================================================================

@celery_app.task(bind=True, name='tasks.run_case_analysis', time_limit=86400, soft_time_limit=85800, acks_late=False, reject_on_worker_lost=False, max_retries=0)
def run_case_analysis(self, case_id: int) -> Dict[str, Any]:
    """
    Run full case analysis pipeline.
    
    This is a long-running task that:
    1. Builds behavioral profiles for all users/systems
    2. Creates peer groups for comparison
    3. Runs gap detection (spraying, brute force, behavioral anomalies)
    4. Correlates Hayabusa detections into attack chains
    5. Runs pattern analysis (AI-enhanced if available)
    6. Enriches with OpenCTI (if available)
    7. Generates suggested actions for analyst review
    
    Args:
        case_id: The case to analyze
        
    Returns:
        dict: {
            'success': bool,
            'analysis_id': str,
            'mode': str,
            'summary': dict (findings counts, etc.)
        }
    """
    from utils.case_analyzer import CaseAnalyzer, AnalysisError
    
    app = get_flask_app()
    
    with app.app_context():
        from models.case import Case
        from models.database import db
        
        # Verify case exists
        case = Case.query.get(case_id)
        if not case:
            return {
                'success': False,
                'error': f'Case {case_id} not found'
            }
        
        # Hook up progress callback to Celery task state
        def progress_callback(phase: str, percent: int, message: str):
            self.update_state(
                state='PROGRESS',
                meta={
                    'phase': phase,
                    'percent': percent,
                    'message': message
                }
            )
        
        try:
            analyzer = CaseAnalyzer(case_id, progress_callback)
            analysis_id = analyzer.run_full_analysis()
            
            results = analyzer.get_results()
            
            return {
                'success': True,
                'analysis_id': analysis_id,
                'case_id': case_id,
                'mode': results.get('mode', 'A'),
                'summary': results.get('summary', {}),
                'gap_findings': results.get('gap_findings', 0),
                'attack_chains': results.get('attack_chains', 0),
                'total_findings': results.get('total_findings', 0)
            }
            
        except AnalysisError as e:
            logger.error(f"[CaseAnalysis] Analysis failed for case {case_id}: {e}")
            return {
                'success': False,
                'case_id': case_id,
                'error': str(e)
            }
        except Exception as e:
            logger.error(f"[CaseAnalysis] Unexpected error for case {case_id}: {e}", exc_info=True)
            return {
                'success': False,
                'case_id': case_id,
                'error': f'Unexpected error: {str(e)}'
            }


@celery_app.task(bind=True, name='tasks.get_analysis_status')
def get_analysis_status(self, analysis_id: str) -> Dict[str, Any]:
    """
    Get the status of a running or completed analysis.
    
    Args:
        analysis_id: UUID of the analysis run
        
    Returns:
        dict: Analysis status and progress
    """
    app = get_flask_app()
    
    with app.app_context():
        from models.behavioral_profiles import CaseAnalysisRun
        
        run = CaseAnalysisRun.query.filter_by(analysis_id=analysis_id).first()
        
        if not run:
            return {
                'found': False,
                'error': f'Analysis {analysis_id} not found'
            }
        
        return {
            'found': True,
            'analysis_id': analysis_id,
            'case_id': run.case_id,
            'status': run.status,
            'mode': run.mode,
            'progress_percent': run.progress_percent,
            'current_phase': run.current_phase,
            'status_message': run.status_message,
            'started_at': run.started_at.isoformat() if run.started_at else None,
            'completed_at': run.completed_at.isoformat() if run.completed_at else None,
            'last_progress_at': run.last_progress_at.isoformat() if run.last_progress_at else None,
            'partial_results_available': run.has_partial_results(),
            'summary': run.summary,
            'error_message': run.error_message
        }


# =============================================================================
# PARALLEL ANALYSIS SUBTASKS
# =============================================================================

@celery_app.task(bind=True, name='tasks.analyze_phase_profile', time_limit=3600, soft_time_limit=3500)
def analyze_phase_profile(self, case_id: int, analysis_id: str) -> Dict[str, Any]:
    """Run behavioral profiling + peer clustering (parallel subtask).
    
    These two phases are sequential (clustering depends on profiles)
    but run in parallel with gap detection and Hayabusa correlation.
    
    Returns:
        dict with profiling and clustering stats
    """
    app = get_flask_app()
    with app.app_context():
        started = time.time()
        try:
            from pipeline.baselines import run_build_baselines

            baseline_result = run_build_baselines(case_id=case_id, analysis_id=analysis_id)
            
            return {
                'success': True,
                'phase': 'profile_cluster',
                'users_profiled': baseline_result.get('users_profiled', 0),
                'systems_profiled': baseline_result.get('systems_profiled', 0),
                'user_groups': baseline_result.get('user_groups', 0),
                'system_groups': baseline_result.get('system_groups', 0),
                'duration_seconds': round(time.time() - started, 3),
            }
        except Exception as e:
            logger.error(f"[ParallelAnalysis] Profiling failed for case {case_id}: {e}", exc_info=True)
            return {
                'success': False,
                'phase': 'profile_cluster',
                'error': str(e),
                'duration_seconds': round(time.time() - started, 3),
            }


@celery_app.task(bind=True, name='tasks.analyze_phase_gaps', time_limit=3600, soft_time_limit=3500)
def analyze_phase_gaps(self, case_id: int, analysis_id: str) -> Dict[str, Any]:
    """Run gap detection (parallel subtask).
    
    Runs all gap detectors (brute force, password spraying, behavioral anomaly).
    Independent of profiling.
    
    Returns:
        dict with gap detection findings count
    """
    app = get_flask_app()
    with app.app_context():
        started = time.time()
        try:
            from pipeline.detect_anomalies import run_detect_anomalies

            findings = run_detect_anomalies(case_id=case_id, analysis_id=analysis_id)

            return {
                'success': True,
                'phase': 'gap_detection',
                'findings_count': len(findings),
                'duration_seconds': round(time.time() - started, 3),
            }
        except Exception as e:
            logger.error(f"[ParallelAnalysis] Gap detection failed for case {case_id}: {e}", exc_info=True)
            return {
                'success': False,
                'phase': 'gap_detection',
                'error': str(e),
                'duration_seconds': round(time.time() - started, 3),
            }


@celery_app.task(bind=True, name='tasks.analyze_phase_hayabusa', time_limit=3600, soft_time_limit=3500)
def analyze_phase_hayabusa(self, case_id: int, analysis_id: str) -> Dict[str, Any]:
    """Run Hayabusa correlation + attack chain building (parallel subtask).
    
    Independent of profiling and gap detection.
    
    Returns:
        dict with attack chains count
    """
    app = get_flask_app()
    with app.app_context():
        started = time.time()
        try:
            from pipeline.detect import run_hayabusa_correlation

            result = run_hayabusa_correlation(case_id=case_id, analysis_id=analysis_id)
            detection_groups = result.get('detection_groups', [])
            attack_chains = result.get('attack_chains', [])
            
            return {
                'success': True,
                'phase': 'hayabusa_correlation',
                'detection_groups': len(detection_groups) if detection_groups else 0,
                'attack_chains': len(attack_chains),
                'finding_summaries': detection_groups or [],
                'attack_chain_summaries': [
                    chain.to_dict() if hasattr(chain, 'to_dict') else chain
                    for chain in attack_chains
                ],
                'duration_seconds': round(time.time() - started, 3),
            }
        except Exception as e:
            logger.error(f"[ParallelAnalysis] Hayabusa correlation failed for case {case_id}: {e}", exc_info=True)
            return {
                'success': False,
                'phase': 'hayabusa_correlation',
                'error': str(e),
                'duration_seconds': round(time.time() - started, 3),
            }


# =============================================================================
# OPENCTI SYNC TASKS
# =============================================================================

@celery_app.task(bind=True, name='tasks.rag_sync_opencti_patterns')
def rag_sync_opencti_patterns(self, triggered_by: str = 'system') -> Dict[str, Any]:
    """
    Sync attack patterns from OpenCTI to local pattern store
    
    Run periodically (daily) to keep patterns current.
    Requires both OPENCTI_ENABLED and OPENCTI_RAG_SYNC to be true.
    
    Args:
        triggered_by: Username who triggered the sync
        
    Returns:
        Dict with sync results
    """
    from utils.opencti import get_opencti_client
    from models.database import db
    from models.system_settings import SystemSettings, SettingKeys
    from utils.licensing.license_manager import LicenseManager
    
    app = get_flask_app()
    
    with app.app_context():
        from models.rag import AttackPattern, RAGSyncLog
        from utils.pattern_overlay import (
            apply_overlay_sync_summary,
            build_opencti_mitre_overlay_payload,
            build_opencti_sigma_companion_queries,
            build_opencti_sigma_overlay_payload,
            summarize_overlay_sync_results,
            sync_external_pattern_overlays,
        )
        from utils.sigma_converter import SigmaToPatternConverter
        
        if not LicenseManager.is_feature_activated('opencti'):
            return {
                'success': False,
                'error': 'OpenCTI is not licensed or activation is not currently active'
            }

        # Check if OpenCTI RAG sync is enabled
        opencti_enabled = SystemSettings.get(SettingKeys.OPENCTI_ENABLED, False)
        rag_sync_enabled = SystemSettings.get(SettingKeys.OPENCTI_RAG_SYNC, False)
        
        if not opencti_enabled or not rag_sync_enabled:
            return {
                'success': False,
                'error': 'OpenCTI RAG sync is disabled in settings'
            }
        
        # Create sync log
        sync_log = RAGSyncLog(
            source='opencti',
            sync_type='full',
            triggered_by=triggered_by
        )
        db.session.add(sync_log)
        db.session.commit()
        
        client = get_opencti_client()
        if not client:
            finalize_rag_sync_log(
                sync_log,
                success=False,
                error_message='OpenCTI not configured or disabled',
            )
            db.session.commit()
            return {'success': False, 'error': 'OpenCTI not configured'}
        
        if client.init_error:
            finalize_rag_sync_log(
                sync_log,
                success=False,
                error_message=client.init_error,
            )
            db.session.commit()
            return {'success': False, 'error': client.init_error}
        
        stats = {
            'attack_patterns': 0,
            'indicators': 0,
            'updated': 0,
            'overlays_added': 0,
            'overlays_updated': 0,
        }
        converter = SigmaToPatternConverter()
        
        self.update_state(state='PROGRESS', meta={'stage': 'attack_patterns', 'progress': 10})
        
        # Sync Attack Patterns
        try:
            patterns = client.get_attack_patterns(limit=500)
            
            for pattern in patterns:
                if not pattern.get('mitre_id'):
                    continue

                normalized_pattern = normalize_opencti_attack_pattern(pattern)
                payload = build_attack_pattern_payload(
                    normalized_pattern,
                    last_synced_at=datetime.utcnow(),
                    created_by='opencti_sync',
                    enabled=True,
                )
                
                existing = AttackPattern.query.filter_by(
                    **resolve_attack_pattern_lookup(normalized_pattern)
                ).first()
                
                created, _ = persist_attack_pattern_payload(
                    existing,
                    payload,
                    model_class=AttackPattern,
                    db_session=db.session,
                    update_fields=OPENCTI_ATTACK_PATTERN_UPDATE_FIELDS,
                )
                apply_pattern_sync_result(
                    stats,
                    created=created,
                    added_key='attack_patterns',
                    updated_key='updated',
                )

                overlay_results = sync_external_pattern_overlays(
                    external_name=pattern.get('name', ''),
                    mitre_techniques=[pattern.get('mitre_id')],
                    payload_builder=lambda match: build_opencti_mitre_overlay_payload(pattern, match),
                )
                overlay_summary = summarize_overlay_sync_results(overlay_results)
                apply_overlay_sync_summary(stats, overlay_summary)
        except Exception as e:
            logger.error(f"[RAG] Error syncing attack patterns: {e}")
        
        self.update_state(state='PROGRESS', meta={'stage': 'indicators', 'progress': 50})
        
        # Sync Indicators with Sigma patterns
        try:
            indicators = client.get_indicators_with_patterns(limit=500)
            
            for ind in indicators:
                if ind.get('pattern_type') != 'sigma' or not ind.get('pattern'):
                    continue

                normalized_indicator = normalize_opencti_sigma_indicator(ind)
                payload = build_attack_pattern_payload(
                    normalized_indicator,
                    last_synced_at=datetime.utcnow(),
                    created_by='opencti_sync',
                    enabled=True,
                )
                
                existing = AttackPattern.query.filter_by(
                    **resolve_attack_pattern_lookup(normalized_indicator)
                ).first()
                
                created, _ = persist_attack_pattern_payload(
                    existing,
                    payload,
                    model_class=AttackPattern,
                    db_session=db.session,
                    allow_update=False,
                )
                apply_pattern_sync_result(
                    stats,
                    created=created,
                    added_key='indicators',
                )

                converted_sigma = converter.convert_sigma_rule(
                    ind['pattern'],
                    source='opencti_sigma',
                )
                sigma_techniques = []
                if converted_sigma and converted_sigma.get('mitre_technique'):
                    sigma_techniques = [converted_sigma['mitre_technique']]
                companion_queries = build_opencti_sigma_companion_queries(converted_sigma)

                overlay_results = sync_external_pattern_overlays(
                    external_name=ind.get('name', ''),
                    mitre_techniques=sigma_techniques,
                    aliases=[ind.get('name')],
                    labels=ind.get('labels', []),
                    payload_builder=lambda match: build_opencti_sigma_overlay_payload(
                        ind,
                        match,
                        sigma_techniques=sigma_techniques,
                        companion_queries=companion_queries,
                    ),
                )
                overlay_summary = summarize_overlay_sync_results(overlay_results)
                apply_overlay_sync_summary(stats, overlay_summary)
        except Exception as e:
            logger.error(f"[RAG] Error syncing indicators: {e}")
        
        db.session.commit()
        
        # Update sync log
        finalize_rag_sync_log(
            sync_log,
            patterns_added=stats['attack_patterns'] + stats['indicators'],
            patterns_updated=(
                stats['updated'] + stats['overlays_updated']
            ),
        )
        db.session.commit()
        
        # Update vector store
        self.update_state(state='PROGRESS', meta={'stage': 'vectorizing', 'progress': 80})
        try:
            _update_pattern_vectors()
        except Exception as e:
            logger.warning(f"[RAG] Vector update failed: {e}")
        
        return build_opencti_sync_response(stats)


@celery_app.task(bind=True, name='tasks.rag_sync_mitre_attack')
def rag_sync_mitre_attack(
    self,
    categories: Optional[List[str]] = None,
    triggered_by: str = 'system'
) -> Dict[str, Any]:
    """
    Sync MITRE ATT&CK patterns and convert to CaseScope detection rules
    
    Downloads latest ATT&CK STIX 2.0 data from GitHub and creates/updates
    pattern rules with ClickHouse detection queries.
    
    Run monthly or on-demand to stay current with ATT&CK updates.
    
    Args:
        categories: Optional list of ATT&CK tactics to sync (e.g., ['credential-access'])
        triggered_by: Username who triggered the sync
        
    Returns:
        Dict with sync results
    """
    from utils.mitre_attack_sync import MitreAttackSync
    from models.database import db
    from models.rag import AttackPattern, RAGSyncLog
    
    app = get_flask_app()
    
    with app.app_context():
        self.update_state(state='PROGRESS', meta={
            'stage': 'fetching',
            'progress': 0,
            'status': 'Downloading MITRE ATT&CK data...'
        })
        
        stats = {
            'new_patterns': 0,
            'updated_patterns': 0,
            'skipped': 0,
            'errors': 0
        }
        
        try:
            # Initialize syncer
            syncer = MitreAttackSync()
            
            # Fetch and convert patterns
            logger.info(f"[MITRE ATT&CK] Starting sync for categories: {categories or 'all'}")
            attack_patterns = syncer.sync_patterns(categories=categories)
            
            self.update_state(state='PROGRESS', meta={
                'stage': 'processing',
                'progress': 30,
                'status': f'Processing {len(attack_patterns)} ATT&CK patterns...'
            })
            
            # Import patterns to database
            for idx, pattern_data in enumerate(attack_patterns):
                try:
                    # Update progress
                    if idx % 10 == 0:
                        progress = 30 + int((idx / len(attack_patterns)) * 50)
                        self.update_state(state='PROGRESS', meta={
                            'stage': 'processing',
                            'progress': progress,
                            'status': f'Processing pattern {idx+1}/{len(attack_patterns)}: {pattern_data["name"]}'
                        })
                    
                    normalized_pattern = normalize_mitre_attack_pattern(pattern_data)
                    payload = build_attack_pattern_payload(
                        normalized_pattern,
                        last_synced_at=datetime.utcnow(),
                        created_by=triggered_by,
                        enabled=True,
                    )
                    existing = AttackPattern.query.filter_by(
                        **resolve_attack_pattern_lookup(normalized_pattern)
                    ).first()
                    
                    created, _ = persist_attack_pattern_payload(
                        existing,
                        payload,
                        model_class=AttackPattern,
                        db_session=db.session,
                        update_fields=SYNC_ATTACK_PATTERN_UPDATE_FIELDS,
                        update_name=True,
                    )
                    apply_pattern_sync_result(
                        stats,
                        created=created,
                        added_key='new_patterns',
                        updated_key='updated_patterns',
                    )
                    
                except Exception as e:
                    logger.error(f"[MITRE ATT&CK] Error processing pattern {pattern_data.get('id')}: {e}")
                    stats['errors'] += 1
                    continue
            
            # Commit all changes
            db.session.commit()
            
            # Log sync
            sync_log = RAGSyncLog(
                source='mitre_attack_v18',
                sync_type='mitre_attack',
                triggered_by=triggered_by
            )
            finalize_rag_sync_log(
                sync_log,
                patterns_added=stats['new_patterns'],
                patterns_updated=stats['updated_patterns'],
            )
            db.session.add(sync_log)
            db.session.commit()
            
            logger.info(f"[MITRE ATT&CK] Sync complete: {stats}")
            
            return build_mitre_sync_response(stats)
            
        except Exception as e:
            logger.error(f"[MITRE ATT&CK] Sync failed: {e}")
            
            return {
                'success': False,
                'error': str(e),
                'stats': stats
            }


def _get_semantic_pattern_suggestions(
    case_id: int,
    client,
    limit: int = 30,
    score_threshold: float = None
) -> Tuple[List[int], Dict[str, Any]]:
    """
    Use semantic search to find patterns relevant to case events.
    
    Samples high-severity and diverse events from the case, embeds them,
    and finds semantically similar attack patterns.
    
    Args:
        case_id: Case ID to analyze
        client: ClickHouse client
        limit: Max patterns to return
        score_threshold: Minimum similarity score
        
    Returns:
        Tuple of (pattern_ids, metadata dict with scores and timing)
    """
    import time
    from utils.rag_embeddings import embed_event_context
    from utils.rag_vectorstore import search_similar_patterns
    
    metadata = {
        'method': 'semantic',
        'events_sampled': 0,
        'patterns_found': 0,
        'avg_score': None,
        'duration_ms': 0
    }
    
    start_time = time.time()
    
    try:
        # Sample diverse events for embedding
        # Priority: high-severity rules, then diverse event types
        sample_query = """
        SELECT 
            event_id,
            channel,
            rule_title,
            rule_level,
            process_name,
            command_line,
            username
        FROM events
        WHERE case_id = {case_id:UInt32}
            AND (noise_matched = false OR noise_matched IS NULL)
        ORDER BY 
            CASE 
                WHEN rule_level = 'critical' THEN 1
                WHEN rule_level = 'high' THEN 2
                WHEN rule_level = 'medium' THEN 3
                ELSE 4
            END,
            rand()
        LIMIT 25
        """
        
        result = client.query(sample_query, parameters={'case_id': case_id})
        
        if not result.result_rows:
            logger.info(f"[Semantic] No events to sample for case {case_id}")
            return [], metadata
        
        # Convert to event dicts for embedding
        events = []
        for row in result.result_rows:
            events.append({
                'event_id': row[0],
                'channel': row[1],
                'rule_title': row[2],
                'rule_level': row[3],
                'process_name': row[4],
                'command_line': row[5][:200] if row[5] else None,
                'username': row[6]
            })
        
        metadata['events_sampled'] = len(events)
        
        # Embed event context
        event_embedding = embed_event_context(events)
        
        # Search for similar patterns
        similar_patterns = search_similar_patterns(
            event_embedding,
            limit=limit,
            score_threshold=score_threshold
        )
        
        if not similar_patterns:
            logger.info(f"[Semantic] No patterns matched above threshold {score_threshold}")
            return [], metadata
        
        # Extract pattern IDs and calculate scores
        pattern_ids = [p['id'] for p in similar_patterns]
        scores = [p['score'] for p in similar_patterns]
        
        metadata['patterns_found'] = len(pattern_ids)
        metadata['avg_score'] = sum(scores) / len(scores) if scores else None
        metadata['top_score'] = max(scores) if scores else None
        metadata['min_score'] = min(scores) if scores else None
        metadata['duration_ms'] = int((time.time() - start_time) * 1000)
        
        logger.info(f"[Semantic] Found {len(pattern_ids)} patterns for case {case_id} "
                   f"(avg score: {metadata['avg_score']:.3f})")
        
        return pattern_ids, metadata
        
    except Exception as e:
        logger.warning(f"[Semantic] Pattern suggestion failed: {e}")
        metadata['error'] = str(e)
        metadata['duration_ms'] = int((time.time() - start_time) * 1000)
        return [], metadata


@celery_app.task(bind=True, name='tasks.rag_discover_patterns')
def rag_discover_patterns(
    self,
    case_id: int,
    case_uuid: str,
    pattern_ids: List[int] = None,
    use_semantic: bool = True,
    semantic_only: bool = False
) -> Dict[str, Any]:
    """
    Scan case events for matching attack patterns
    
    Uses a hybrid approach:
    1. Semantic search to find patterns relevant to case events (prioritized)
    2. SQL-based pattern matching to verify and find additional matches
    
    Args:
        case_id: PostgreSQL case.id (used as ClickHouse case_id)
        case_uuid: Case UUID
        pattern_ids: Optional list of specific pattern IDs to check
        use_semantic: Whether to use semantic search to prioritize patterns (default True)
        semantic_only: If True, only check semantically-matched patterns (faster but may miss some)
        
    Returns:
        Dict with discovery results
    """
    from utils.clickhouse import get_fresh_client
    from models.database import db
    
    app = get_flask_app()
    
    with app.app_context():
        from models.rag import AttackPattern, PatternMatch
        
        client = get_fresh_client()
        
        semantic_metadata = {'method': 'sql_only'}
        
        # Get event count
        count_result = client.query(
            "SELECT count() FROM events WHERE case_id = {case_id:UInt32}",
            parameters={'case_id': case_id}
        )
        total_events = count_result.result_rows[0][0] if count_result.result_rows else 0
        
        self.update_state(state='PROGRESS', meta={
            'progress': 0,
            'status': f'Scanning {total_events:,} events...',
            'total_events': total_events
        })
        
        # Step 1: Try semantic discovery first (if enabled and no specific patterns requested)
        semantic_pattern_ids = []
        if use_semantic and not pattern_ids and total_events > 0:
            self.update_state(state='PROGRESS', meta={
                'progress': 5,
                'status': 'Analyzing events with semantic search...',
                'total_events': total_events
            })
            
            # Use centralized threshold from config
            from config import Config
            discovery_threshold = getattr(Config, 'RAG_PATTERN_DISCOVERY_THRESHOLD', 0.40)
            
            semantic_pattern_ids, semantic_metadata = _get_semantic_pattern_suggestions(
                case_id=case_id,
                client=client,
                limit=50,
                score_threshold=discovery_threshold
            )
            
            if semantic_pattern_ids:
                logger.info(f"[RAG] Semantic search found {len(semantic_pattern_ids)} relevant patterns")
        
        # Step 2: Get patterns to check
        if pattern_ids:
            # User specified exact patterns
            patterns = AttackPattern.query.filter(
                AttackPattern.id.in_(pattern_ids),
                AttackPattern.enabled == True
            ).all()
        elif semantic_pattern_ids and semantic_only:
            # Only use semantically-matched patterns (faster)
            patterns = AttackPattern.query.filter(
                AttackPattern.id.in_(semantic_pattern_ids),
                AttackPattern.enabled == True
            ).all()
            logger.info(f"[RAG] Semantic-only mode: checking {len(patterns)} patterns")
        elif semantic_pattern_ids:
            # Prioritize semantic patterns, but also check others
            # Get semantic matches first, then remaining patterns
            semantic_patterns = AttackPattern.query.filter(
                AttackPattern.id.in_(semantic_pattern_ids),
                AttackPattern.enabled == True
            ).all()
            
            remaining_patterns = AttackPattern.query.filter(
                ~AttackPattern.id.in_(semantic_pattern_ids),
                AttackPattern.enabled == True
            ).all()
            
            # Order: semantic first (by score), then remaining
            patterns = semantic_patterns + remaining_patterns
            logger.info(f"[RAG] Hybrid mode: {len(semantic_patterns)} semantic + {len(remaining_patterns)} fallback patterns")
        else:
            # No semantic results or disabled - check all patterns
            patterns = AttackPattern.query.filter_by(enabled=True).all()
        
        # Filter to patterns with ClickHouse queries
        executable_patterns = [p for p in patterns if p.clickhouse_query]
        
        matches_found = []
        errors = []
        
        # Noise filter to exclude events marked as noise
        noise_filter = " AND (noise_matched = false OR noise_matched IS NULL)"
        
        for idx, pattern in enumerate(executable_patterns):
            try:
                # Inject noise filter into query - add after WHERE clause conditions
                query_with_noise = pattern.clickhouse_query
                # Insert noise filter before GROUP BY, HAVING, ORDER BY, or LIMIT
                for keyword in ['GROUP BY', 'HAVING', 'ORDER BY', 'LIMIT']:
                    if keyword in query_with_noise.upper():
                        # Find position (case insensitive)
                        import re
                        match = re.search(keyword, query_with_noise, re.IGNORECASE)
                        if match:
                            pos = match.start()
                            query_with_noise = query_with_noise[:pos] + noise_filter + ' ' + query_with_noise[pos:]
                            break
                else:
                    # No GROUP BY/HAVING/ORDER BY/LIMIT found, append to end
                    query_with_noise = query_with_noise.rstrip() + noise_filter
                
                # Execute pattern query - check for parameterized syntax first
                if '{case_id:UInt32}' in query_with_noise:
                    query = query_with_noise
                elif '{case_id}' in query_with_noise:
                    query = query_with_noise.replace('{case_id}', '{case_id:UInt32}')
                else:
                    logger.warning(
                        f"[RAG] Skipping pattern {pattern.name} without supported case_id placeholder"
                    )
                    continue

                result = client.query(
                    query,
                    parameters={'case_id': case_id}
                )
                
                if result.result_rows:
                    for row in result.result_rows:
                        # Convert row to dict
                        row_dict = {}
                        if result.column_names:
                            for i, col in enumerate(result.column_names):
                                if i < len(row):
                                    row_dict[col] = row[i]
                        
                        # Check if match already exists
                        source_host = row_dict.get('source_host', '')
                        existing = PatternMatch.query.filter_by(
                            case_id=case_id,
                            pattern_id=pattern.id,
                            source_host=source_host
                        ).first()
                        
                        if not existing:
                            # Parse timestamps if present
                            first_time = None
                            last_time = None
                            if row_dict.get('first_fail'):
                                first_time = row_dict['first_fail']
                            if row_dict.get('last_fail'):
                                last_time = row_dict['last_fail']
                            if row_dict.get('timestamp'):
                                first_time = first_time or row_dict['timestamp']
                                last_time = row_dict['timestamp']
                            
                            # Calculate time span
                            time_span = None
                            if row_dict.get('delay_seconds'):
                                time_span = int(row_dict['delay_seconds'])
                            
                            match = PatternMatch(
                                case_id=case_id,
                                pattern_id=pattern.id,
                                confidence_score=pattern.confidence_weight,
                                matched_event_count=row_dict.get('fail_count', 1),
                                time_span_seconds=time_span,
                                first_event_time=first_time if isinstance(first_time, datetime) else None,
                                last_event_time=last_time if isinstance(last_time, datetime) else None,
                                source_host=source_host,
                                affected_users=[row_dict['username']] if row_dict.get('username') else None,
                                matched_events={'raw': str(row_dict)[:1000]},
                            )
                            db.session.add(match)
                            
                            matches_found.append({
                                'pattern': pattern.name,
                                'mitre': pattern.mitre_technique,
                                'confidence': pattern.confidence_weight,
                                'source_host': source_host,
                                'event_count': row_dict.get('fail_count', 1)
                            })
                            
            except Exception as e:
                logger.warning(f"[RAG] Pattern {pattern.name} query failed: {e}")
                errors.append(f"{pattern.name}: {str(e)[:100]}")
            
            # Update progress
            progress = int(((idx + 1) / len(executable_patterns)) * 100)
            self.update_state(state='PROGRESS', meta={
                'progress': progress,
                'status': f'Checked {idx + 1}/{len(executable_patterns)} patterns',
                'matches_found': len(matches_found)
            })
        
        db.session.commit()
        
        return {
            'success': True,
            'case_id': case_id,
            'case_uuid': case_uuid,
            'total_events': total_events,
            'patterns_checked': len(executable_patterns),
            'patterns_total': len(patterns),
            'matches_found': len(matches_found),
            'matches': matches_found[:50],  # Limit response size
            'errors': errors[:10] if errors else None,
            'semantic': semantic_metadata
        }


@celery_app.task(bind=True, name='tasks.rag_detect_campaigns')
def rag_detect_campaigns(
    self,
    case_id: int,
    case_uuid: str
) -> Dict[str, Any]:
    """
    Detect attack campaigns by analyzing pattern matches and running campaign queries.
    
    Campaigns are high-level attack behaviors composed of multiple indicators,
    such as password spray, lateral movement chains, Cobalt Strike, etc.
    
    Args:
        case_id: PostgreSQL case.id
        case_uuid: Case UUID
        
    Returns:
        Dict with detected campaigns
    """
    from utils.clickhouse import get_fresh_client
    from models.database import db
    
    app = get_flask_app()
    
    with app.app_context():
        from models.rag import AttackCampaign, PatternMatch, CAMPAIGN_TEMPLATES
        
        # Initialize hunting logger
        hunt_log = get_hunting_logger(case_id=case_id, case_uuid=case_uuid)
        hunt_log.log_start('rag_detect_campaigns')
        
        client = get_fresh_client()
        
        self.update_state(state='PROGRESS', meta={
            'progress': 5,
            'status': 'Initializing campaign detection...'
        })
        
        # Clear existing campaigns for this case (will regenerate)
        AttackCampaign.query.filter_by(case_id=case_id).delete()
        db.session.commit()
        hunt_log.info(f"Cleared existing campaigns for case {case_id}")
        
        campaigns_detected = []
        errors = []
        error_count = 0
        
        total_templates = len(CAMPAIGN_TEMPLATES)
        hunt_log.info(f"Will check {total_templates} campaign templates")
        
        # Noise filter to exclude events marked as noise
        noise_filter = " AND (noise_matched = false OR noise_matched IS NULL)"
        
        for idx, template in enumerate(CAMPAIGN_TEMPLATES):
            try:
                progress = int(((idx + 1) / total_templates) * 90) + 5
                self.update_state(state='PROGRESS', meta={
                    'progress': progress,
                    'status': f'Checking: {template["name"]}...',
                    'campaigns_found': len(campaigns_detected)
                })
                
                hunt_log.log_campaign_start(template['name'])
                
                # Run detection query with noise filtering
                if template.get('detection_query'):
                    # Inject noise filter into query
                    import re
                    query_with_noise = template['detection_query']
                    for keyword in ['GROUP BY', 'HAVING', 'ORDER BY', 'LIMIT']:
                        match = re.search(keyword, query_with_noise, re.IGNORECASE)
                        if match:
                            pos = match.start()
                            query_with_noise = query_with_noise[:pos] + noise_filter + ' ' + query_with_noise[pos:]
                            break
                    else:
                        query_with_noise = query_with_noise.rstrip() + noise_filter
                    
                    result = client.query(
                        query_with_noise,
                        parameters={'case_id': case_id}
                    )
                    
                    if result.result_rows:
                        for row in result.result_rows:
                            # Convert row to dict
                            row_dict = {}
                            if result.column_names:
                                for i, col in enumerate(result.column_names):
                                    if i < len(row):
                                        row_dict[col] = row[i]
                            
                            # Extract data based on campaign type
                            affected_hosts = []
                            affected_users = []
                            first_activity = None
                            last_activity = None
                            indicator_count = 1
                            
                            # Handle hosts
                            if row_dict.get('source_host'):
                                affected_hosts = [row_dict['source_host']]
                            elif row_dict.get('source_hosts'):
                                affected_hosts = list(row_dict['source_hosts']) if row_dict['source_hosts'] else []
                            elif row_dict.get('host_list'):
                                affected_hosts = list(row_dict['host_list']) if row_dict['host_list'] else []
                            
                            # Handle users
                            if row_dict.get('username'):
                                affected_users = [row_dict['username']]
                            elif row_dict.get('usernames'):
                                affected_users = list(row_dict['usernames']) if row_dict['usernames'] else []
                            
                            # Handle timestamps
                            for ts_field in ['first_fail', 'first_seen', 'first_access', 'first_activity']:
                                if row_dict.get(ts_field):
                                    first_activity = row_dict[ts_field]
                                    break
                            for ts_field in ['last_fail', 'last_seen', 'last_access', 'last_activity']:
                                if row_dict.get(ts_field):
                                    last_activity = row_dict[ts_field]
                                    break
                            
                            # Get indicator count
                            for count_field in ['total_failures', 'fail_count', 'suspicious_events', 
                                               'dump_events', 'exfil_indicators', 'total_persistence']:
                                if row_dict.get(count_field):
                                    indicator_count = row_dict[count_field]
                                    break
                            
                            # Calculate duration
                            duration_seconds = None
                            if row_dict.get('duration_secs'):
                                duration_seconds = int(row_dict['duration_secs'])
                            elif first_activity and last_activity:
                                try:
                                    duration_seconds = int((last_activity - first_activity).total_seconds())
                                except:
                                    pass
                            
                            # Calculate confidence based on thresholds met
                            confidence = 0.7  # Base confidence
                            thresholds = template.get('thresholds', {})
                            if row_dict.get('unique_users', 0) >= thresholds.get('min_users', 0):
                                confidence += 0.1
                            if row_dict.get('hosts_accessed', 0) >= thresholds.get('min_hosts', 0):
                                confidence += 0.1
                            if indicator_count >= 5:
                                confidence += 0.1
                            confidence = min(confidence, 0.99)
                            
                            # Build description
                            description = template['description']
                            if template['type'] == 'password_spray':
                                description = f"Password spray detected: {row_dict.get('unique_users', 0)} accounts targeted, {row_dict.get('total_failures', 0)} total failures"
                            elif template['type'] == 'brute_force':
                                description = f"Brute force against '{row_dict.get('username', 'unknown')}': {row_dict.get('fail_count', 0)} failures in {row_dict.get('duration_secs', 0)}s"
                            elif template['type'] == 'lateral_movement_chain':
                                description = f"Lateral movement by '{row_dict.get('username', 'unknown')}' across {row_dict.get('hosts_accessed', 0)} hosts"
                            elif template['type'] == 'credential_dumping':
                                description = f"Credential dumping detected on {', '.join(affected_hosts[:3])}"
                            elif template['type'] == 'ransomware_precursor':
                                description = f"Ransomware preparation detected: shadow copy/backup disruption"
                            
                            # Check if campaign already exists (dedup by type + hosts)
                            existing = AttackCampaign.query.filter_by(
                                case_id=case_id,
                                campaign_type=template['type']
                            ).filter(
                                AttackCampaign.affected_hosts.contains(affected_hosts[:1]) if affected_hosts else True
                            ).first()
                            
                            if not existing:
                                campaign = AttackCampaign(
                                    case_id=case_id,
                                    campaign_type=template['type'],
                                    campaign_name=template['name'],
                                    description=description,
                                    confidence_score=confidence,
                                    severity=template['severity'],
                                    affected_hosts=affected_hosts[:50],  # Limit array size
                                    affected_users=affected_users[:50],
                                    host_count=len(affected_hosts),
                                    user_count=len(affected_users),
                                    first_activity=first_activity if isinstance(first_activity, datetime) else None,
                                    last_activity=last_activity if isinstance(last_activity, datetime) else None,
                                    duration_seconds=duration_seconds,
                                    indicator_count=indicator_count,
                                    matched_indicators={'raw': str(row_dict)[:2000]},
                                    mitre_tactics=template.get('mitre_tactics'),
                                    mitre_techniques=template.get('mitre_techniques')
                                )
                                db.session.add(campaign)
                                
                                campaigns_detected.append({
                                    'type': template['type'],
                                    'name': template['name'],
                                    'severity': template['severity'],
                                    'hosts': len(affected_hosts),
                                    'users': len(affected_users),
                                    'confidence': confidence
                                })
                                
                                # Log campaign found
                                hunt_log.log_campaign_found(
                                    campaign_type=template['type'],
                                    campaign_name=template['name'],
                                    hosts_affected=len(affected_hosts),
                                    users_affected=len(affected_users),
                                    confidence=confidence,
                                    severity=template['severity']
                                )
                                
            except Exception as e:
                error_count += 1
                logger.warning(f"[RAG] Campaign detection failed for {template['type']}: {e}")
                hunt_log.error(f"Campaign {template['type']} failed: {str(e)[:200]}")
                errors.append(f"{template['type']}: {str(e)[:100]}")
        
        db.session.commit()
        
        # Also aggregate pattern matches into summary
        pattern_summary = db.session.query(
            PatternMatch.pattern_id,
            db.func.count(PatternMatch.id).label('match_count'),
            db.func.count(db.distinct(PatternMatch.source_host)).label('host_count')
        ).filter(
            PatternMatch.case_id == case_id
        ).group_by(PatternMatch.pattern_id).all()
        
        # Log completion
        hunt_log.log_complete(
            patterns_checked=total_templates,
            matches_found=len(campaigns_detected),
            errors=error_count
        )
        
        return {
            'success': True,
            'case_id': case_id,
            'case_uuid': case_uuid,
            'campaigns_detected': len(campaigns_detected),
            'campaigns': campaigns_detected,
            'pattern_summary': [
                {'pattern_id': p[0], 'matches': p[1], 'hosts': p[2]}
                for p in pattern_summary
            ],
            'errors': errors[:10] if errors else None,
            'log_file': hunt_log.get_log_path()
        }


@celery_app.task(bind=True, name='tasks.rag_hunt_related')
def rag_hunt_related(
    self,
    case_id: int,
    case_uuid: str,
    include_ioc: bool = True,
    include_analyst: bool = True,
    include_sigma_high: bool = True,
    time_window_hours: int = 24
) -> Dict[str, Any]:
    """
    Hunt for events related to tagged/interesting events
    
    Args:
        case_id: PostgreSQL case.id
        case_uuid: Case UUID
        include_ioc: Include IOC-matched events as anchors
        include_analyst: Include analyst-tagged events as anchors
        include_sigma_high: Include high/critical SIGMA hits as anchors
        time_window_hours: Time window around anchor events
        
    Returns:
        Dict with hunting results
    """
    from utils.clickhouse import get_fresh_client
    from models.database import db
    
    app = get_flask_app()
    
    with app.app_context():
        client = get_fresh_client()
        
        self.update_state(state='PROGRESS', meta={
            'progress': 10,
            'status': 'Finding anchor events...'
        })
        
        # Build query for anchor events
        conditions = []
        
        if include_sigma_high:
            conditions.append("rule_level IN ('high', 'critical')")
        
        # IOC and analyst tagging would need ClickHouse columns
        # For now, focus on SIGMA hits
        
        if not conditions:
            return {
                'success': False,
                'error': 'No anchor event types selected'
            }
        
        # Get anchor events
        anchor_query = f"""
            SELECT timestamp, source_host, event_id, channel, username,
                   rule_title, rule_level
            FROM events
            WHERE case_id = {{case_id:UInt32}}
              AND ({' OR '.join(conditions)})
            ORDER BY timestamp
            LIMIT 1000
        """
        
        result = client.query(anchor_query, parameters={'case_id': case_id})
        anchors = result.result_rows
        
        if not anchors:
            return {
                'success': True,
                'message': 'No anchor events found',
                'anchor_count': 0,
                'related_events': []
            }
        
        self.update_state(state='PROGRESS', meta={
            'progress': 30,
            'status': f'Found {len(anchors)} anchor events, hunting related...'
        })
        
        # Group anchors by host for efficiency
        hosts = set()
        time_ranges = []
        for anchor in anchors:
            if anchor[1]:  # source_host
                hosts.add(anchor[1])
            time_ranges.append(anchor[0])  # timestamp
        
        # Find min/max time range
        if time_ranges:
            min_time = min(time_ranges) - timedelta(hours=time_window_hours)
            max_time = max(time_ranges) + timedelta(hours=time_window_hours)
        else:
            return {
                'success': True,
                'message': 'No valid anchor timestamps',
                'anchor_count': len(anchors),
                'related_events': []
            }
        
        self.update_state(state='PROGRESS', meta={
            'progress': 50,
            'status': 'Searching for related events...'
        })
        
        # Query for related events around anchors
        related_query = """
            SELECT timestamp, source_host, event_id, channel, username,
                   rule_title, rule_level, artifact_type
            FROM events
            WHERE case_id = {case_id:UInt32}
              AND timestamp BETWEEN {min_time:DateTime64} AND {max_time:DateTime64}
              AND (rule_level IS NOT NULL OR event_id IN ('4624', '4625', '4688', '7045', '4698', '1102'))
            ORDER BY timestamp
            LIMIT 5000
        """
        
        related_result = client.query(
            related_query,
            parameters={
                'case_id': case_id,
                'min_time': min_time,
                'max_time': max_time
            }
        )
        
        self.update_state(state='PROGRESS', meta={
            'progress': 80,
            'status': 'Processing results...'
        })
        
        # Format results
        related_events = []
        for row in related_result.result_rows[:500]:  # Limit
            related_events.append({
                'timestamp': row[0].isoformat() if row[0] else None,
                'source_host': row[1],
                'event_id': row[2],
                'channel': row[3],
                'username': row[4],
                'rule_title': row[5],
                'rule_level': row[6],
                'artifact_type': row[7]
            })
        
        return {
            'success': True,
            'anchor_count': len(anchors),
            'related_count': len(related_events),
            'time_range': {
                'start': min_time.isoformat(),
                'end': max_time.isoformat()
            },
            'hosts': list(hosts)[:20],
            'related_events': related_events
        }


@celery_app.task(bind=True, name='tasks.rag_generate_timeline')
def rag_generate_timeline(
    self,
    case_id: int,
    case_uuid: str,
    include_sigma: bool = True,
    include_ioc: bool = True,
    include_patterns: bool = True,
    include_analyst: bool = True
) -> Dict[str, Any]:
    """
    Generate incident timeline from tagged events
    
    Args:
        case_id: PostgreSQL case.id
        case_uuid: Case UUID
        include_sigma: Include SIGMA high/critical hits
        include_ioc: Include IOC matches
        include_patterns: Include AI pattern matches
        include_analyst: Include analyst-tagged events
        
    Returns:
        Dict with timeline
    """
    from utils.clickhouse import get_fresh_client
    from utils.rag_llm import generate_timeline_narrative, generate_executive_summary
    from models.database import db
    
    app = get_flask_app()
    
    with app.app_context():
        from models.rag import PatternMatch
        
        client = get_fresh_client()
        
        self.update_state(state='PROGRESS', meta={
            'progress': 10,
            'status': 'Collecting timeline-worthy events...'
        })
        
        # Build query conditions
        conditions = []
        
        if include_sigma:
            conditions.append("rule_level IN ('high', 'critical')")
        
        if not conditions:
            conditions.append("rule_level IN ('high', 'critical')")  # Default
        
        # Query timeline events
        timeline_query = f"""
            SELECT timestamp, source_host, event_id, channel, username,
                   rule_title, rule_level, mitre_tactics, mitre_tags,
                   process_name, command_line
            FROM events
            WHERE case_id = {{case_id:UInt32}}
              AND ({' OR '.join(conditions)})
            ORDER BY timestamp ASC
            LIMIT 2000
        """
        
        result = client.query(timeline_query, parameters={'case_id': case_id})
        events = result.result_rows
        
        if not events:
            return {
                'success': True,
                'message': 'No timeline-worthy events found',
                'timeline': [],
                'phase_count': 0
            }
        
        self.update_state(state='PROGRESS', meta={
            'progress': 30,
            'status': f'Processing {len(events)} events into phases...'
        })
        
        # Get pattern matches for this case
        pattern_matches = []
        if include_patterns:
            matches = PatternMatch.query.filter_by(case_id=case_id).all()
            pattern_matches = [m.to_dict() for m in matches]
        
        # Cluster events into phases (2-hour gap threshold)
        phases = _cluster_into_phases(events, result.column_names, gap_minutes=120)
        
        self.update_state(state='PROGRESS', meta={
            'progress': 50,
            'status': f'Generating narratives for {len(phases)} phases...'
        })
        
        # Generate narratives for each phase
        timeline_entries = []
        for i, phase in enumerate(phases):
            self.update_state(state='PROGRESS', meta={
                'progress': 50 + int((i / len(phases)) * 40),
                'status': f'Generating phase {i + 1}/{len(phases)}...'
            })
            
            # Get MITRE tactics from phase events
            mitre_tactics = set()
            mitre_techniques = set()
            for event in phase['events']:
                if event.get('mitre_tactics'):
                    for tactic in event['mitre_tactics']:
                        if tactic:
                            mitre_tactics.add(tactic)
                if event.get('mitre_tags'):
                    for tag in event['mitre_tags']:
                        if tag:
                            mitre_techniques.add(tag)
            
            # Generate narrative using LLM
            narrative_result = generate_timeline_narrative(
                phase_events=phase['events'],
                phase_number=i + 1,
                total_phases=len(phases),
                mitre_tactics=list(mitre_tactics)
            )
            
            narrative = narrative_result.get('narrative', {})
            
            timeline_entries.append({
                'phase_number': i + 1,
                'start_time': phase['start_time'].isoformat() if phase['start_time'] else None,
                'end_time': phase['end_time'].isoformat() if phase['end_time'] else None,
                'event_count': len(phase['events']),
                'mitre_tactics': list(mitre_tactics),
                'mitre_techniques': list(mitre_techniques),
                'summary': narrative.get('summary', f'Phase {i + 1}: {len(phase["events"])} events'),
                'attacker_objective': narrative.get('objective', 'Unknown'),
                'confidence': narrative.get('confidence', 'medium'),
                'key_indicators': narrative.get('key_indicators', []),
                'source_events': phase['events'][:10]  # Limit for response
            })
        
        self.update_state(state='PROGRESS', meta={
            'progress': 90,
            'status': 'Generating executive summary...'
        })
        
        # Generate executive summary
        exec_summary = generate_executive_summary(timeline_entries)
        
        return {
            'success': True,
            'case_id': case_id,
            'case_uuid': case_uuid,
            'generated_at': datetime.utcnow().isoformat(),
            'total_events': len(events),
            'phase_count': len(timeline_entries),
            'executive_summary': exec_summary,
            'timeline': timeline_entries,
            'pattern_matches': pattern_matches[:20]
        }


def _cluster_into_phases(
    rows: List[tuple],
    column_names: List[str],
    gap_minutes: int = 120
) -> List[Dict]:
    """Cluster events into incident phases based on time gaps"""
    if not rows:
        return []
    
    # Convert rows to dicts
    events = []
    for row in rows:
        event = {}
        for i, col in enumerate(column_names):
            if i < len(row):
                value = row[i]
                # Handle datetime serialization
                if isinstance(value, datetime):
                    event[col] = value
                elif hasattr(value, 'isoformat'):
                    event[col] = value
                else:
                    event[col] = value
        events.append(event)
    
    phases = []
    current_phase = {
        'events': [events[0]],
        'start_time': events[0].get('timestamp'),
        'end_time': events[0].get('timestamp')
    }
    
    for event in events[1:]:
        event_time = event.get('timestamp')
        if not event_time:
            current_phase['events'].append(event)
            continue
        
        phase_end = current_phase['end_time']
        if phase_end:
            gap = (event_time - phase_end).total_seconds() / 60
            
            if gap > gap_minutes:
                # Start new phase
                phases.append(current_phase)
                current_phase = {
                    'events': [event],
                    'start_time': event_time,
                    'end_time': event_time
                }
            else:
                current_phase['events'].append(event)
                current_phase['end_time'] = event_time
        else:
            current_phase['events'].append(event)
            current_phase['end_time'] = event_time
    
    phases.append(current_phase)
    
    # Format events for JSON serialization
    for phase in phases:
        formatted_events = []
        for e in phase['events']:
            formatted = {}
            for k, v in e.items():
                if isinstance(v, datetime):
                    formatted[k] = v.isoformat()
                elif isinstance(v, (list, tuple)):
                    formatted[k] = list(v) if v else []
                else:
                    formatted[k] = v
            formatted_events.append(formatted)
        phase['events'] = formatted_events
    
    return phases


def _build_pattern_text(pattern) -> str:
    """Build rich text representation of a pattern for embedding"""
    parts = [
        f"Attack Pattern: {pattern.name}",
        f"Category: {pattern.mitre_tactic or 'Unknown'}",
        f"MITRE Technique: {pattern.mitre_technique or 'Unknown'}",
    ]
    
    if pattern.description:
        parts.append(f"Description: {pattern.description}")
    
    if pattern.required_event_ids:
        parts.append(f"Event IDs: {', '.join(pattern.required_event_ids)}")
    
    if pattern.required_channels:
        parts.append(f"Channels: {', '.join(pattern.required_channels)}")
    
    return "\n".join(parts)


def _update_pattern_vectors():
    """Update vector embeddings for all patterns using batch processing
    
    Uses batch embedding for GPU acceleration (3.6x faster on A2).
    """
    from models.rag import AttackPattern
    from utils.rag_embeddings import embed_texts
    from utils.rag_vectorstore import upsert_patterns
    from config import Config
    
    app = get_flask_app()
    
    with app.app_context():
        patterns = AttackPattern.query.filter_by(enabled=True).all()
        
        if not patterns:
            logger.info("[RAG] No patterns to vectorize")
            return
        
        logger.info(f"[RAG] Vectorizing {len(patterns)} patterns using batch embedding")
        start_time = time.time()
        
        # Build text representations for all patterns
        pattern_texts = []
        valid_patterns = []
        
        for pattern in patterns:
            try:
                text = _build_pattern_text(pattern)
                pattern_texts.append(text)
                valid_patterns.append(pattern)
            except Exception as e:
                logger.warning(f"[RAG] Failed to build text for pattern {pattern.id}: {e}")
        
        if not pattern_texts:
            logger.warning("[RAG] No valid pattern texts to embed")
            return
        
        # Batch embed all patterns at once (GPU-accelerated)
        batch_size = getattr(Config, 'EMBEDDING_BATCH_SIZE', 128)
        embeddings = embed_texts(pattern_texts, batch_size=batch_size)
        
        # Build vector records
        vectors = []
        for pattern, embedding in zip(valid_patterns, embeddings):
            vectors.append({
                'id': pattern.id,
                'embedding': embedding,
                'payload': {
                    'name': pattern.name,
                    'description': pattern.description[:200] if pattern.description else None,
                    'mitre_tactic': pattern.mitre_tactic,
                    'mitre_technique': pattern.mitre_technique,
                    'severity': pattern.severity,
                    'source': pattern.source
                }
            })
        
        if vectors:
            upsert_patterns(vectors)
            elapsed = time.time() - start_time
            logger.info(f"[RAG] Updated {len(vectors)} pattern vectors in {elapsed:.2f}s ({len(vectors)/elapsed:.1f} patterns/sec)")


@celery_app.task(bind=True, name='tasks.rag_embed_high_severity_events')
def rag_embed_high_severity_events(
    self,
    case_id: int,
    case_uuid: str,
    max_events: int = 5000,
    batch_size: int = 100,
    scope: str = 'high_priority',
    time_start: Optional[str] = None,
    time_end: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Embed a bounded event slice for semantic search.
    
    Supported scopes:
    - high_priority: critical/high detections only
    - analyst_tagged: analyst-selected events
    - ioc_tagged: events with IOC matches
    - time_range: explicit bounded time window
    
    Args:
        case_id: PostgreSQL case.id
        case_uuid: Case UUID
        max_events: Maximum events to embed per case
        batch_size: Batch size for embedding
        scope: Selective embedding scope
        time_start: ISO timestamp for time_range scope
        time_end: ISO timestamp for time_range scope
        
    Returns:
        Dict with embedding results
    """
    from utils.clickhouse import get_fresh_client
    from utils.rag_embeddings import embed_texts
    from utils.rag_vectorstore import get_qdrant_client, ensure_collection
    from config import Config
    
    app = get_flask_app()
    lock_owner = self.request.id or f"case-{case_id}-{scope}"
    
    if not _acquire_event_embedding_lock(case_id, scope, lock_owner):
        logger.info(f"[RAG Events] Skipping overlapping event embedding for case {case_id} scope {scope}")
        return {
            'success': True,
            'case_id': case_id,
            'scope': scope,
            'skipped': True,
            'message': f'Event embedding already in progress for scope {scope}'
        }

    try:
        with app.app_context():
            overall_started = time.time()
            supported_scopes = {'high_priority', 'analyst_tagged', 'ioc_tagged', 'time_range'}
            if scope not in supported_scopes:
                return {
                    'success': False,
                    'error': f'Unsupported embedding scope: {scope}'
                }

            self.update_state(state='PROGRESS', meta={
                'progress': 5,
                'status': f'Querying events for scope {scope}...'
            })

            client = get_fresh_client()
            query_started = time.time()
            conditions = ["case_id = {case_id:UInt32}"]
            scope_conditions, scope_parameters = _build_event_embedding_conditions(
                scope,
                time_start=time_start,
                time_end=time_end,
            )
            conditions.extend(scope_conditions)
            parameters = {
                'case_id': case_id,
                'limit': max_events,
                **scope_parameters,
            }

            query = f"""
                SELECT 
                    record_id,
                    timestamp_utc,
                    event_id,
                    channel,
                    source_host,
                    username,
                    rule_title,
                    rule_level,
                    process_name,
                    substring(command_line, 1, 300) as command_line,
                    mitre_tactics,
                    mitre_tags
                FROM events
                WHERE {' AND '.join(conditions)}
                ORDER BY 
                    multiIf(rule_level IN ('crit', 'critical'), 1, rule_level = 'high', 2, 3) ASC,
                    timestamp_utc DESC
                LIMIT {limit:UInt32}
            """

            result = client.query(query, parameters=parameters)
            query_duration_ms = int((time.time() - query_started) * 1000)

            collection_name = _build_case_event_collection_name(case_id)
            qdrant_client = get_qdrant_client()

            if not result.result_rows:
                vector_store_started = time.time()
                stale_scope_removed = False
                try:
                    stale_scope_removed = _delete_scope_event_vectors(qdrant_client, collection_name, scope)
                except Exception as exc:
                    logger.warning(f"[RAG Events] Failed to clear stale vectors for empty scope {scope}: {exc}")
                vector_store_duration_ms = int((time.time() - vector_store_started) * 1000)
                return {
                    'success': True,
                    'message': f'No events found for scope {scope}',
                    'events_embedded': 0,
                    'scope': scope,
                    'stale_scope_removed': stale_scope_removed,
                    'benchmark': {
                        'query_duration_ms': query_duration_ms,
                        'vector_store_duration_ms': vector_store_duration_ms,
                        'total_duration_ms': int((time.time() - overall_started) * 1000),
                    }
                }

            logger.info(f"[RAG Events] Found {len(result.result_rows)} events for case {case_id} (scope={scope})")

            self.update_state(state='PROGRESS', meta={
                'progress': 20,
                'status': f'Building text representations for {len(result.result_rows)} events...'
            })

            events_data = []
            event_texts = []
            embedded_at = datetime.utcnow().isoformat()

            for row in result.result_rows:
                record_id, ts, eid, ch, host, user, title, level, proc, cmd, tactics, tags = row

                parts = []
                if title:
                    parts.append(f"Rule: {title}")
                if eid:
                    parts.append(f"EventID: {eid}")
                if ch:
                    parts.append(f"Channel: {ch}")
                if host:
                    parts.append(f"Host: {host}")
                if user:
                    parts.append(f"User: {user}")
                if proc:
                    parts.append(f"Process: {proc}")
                if cmd:
                    parts.append(f"Command: {cmd[:200]}")
                if tactics:
                    parts.append(f"MITRE Tactics: {', '.join(tactics)}")
                if tags:
                    parts.append(f"MITRE Techniques: {', '.join(tags)}")

                text = " | ".join(parts) if parts else f"EventID: {eid}"
                event_texts.append(text)

                events_data.append({
                    'record_id': record_id,
                    'timestamp': ts.isoformat() if ts else None,
                    'event_id': eid,
                    'channel': ch,
                    'source_host': host,
                    'username': user,
                    'rule_title': title,
                    'rule_level': level,
                    'process_name': proc,
                    'embedding_scope': scope,
                    'embedded_at': embedded_at,
                    'case_id': case_id,
                    'case_uuid': case_uuid,
                })

            self.update_state(state='PROGRESS', meta={
                'progress': 40,
                'status': f'Embedding {len(event_texts)} events...'
            })

            embedding_started = time.time()
            embedding_batch_size = getattr(Config, 'EMBEDDING_BATCH_SIZE', 128)
            embeddings = embed_texts(event_texts, batch_size=embedding_batch_size)
            embedding_duration_ms = int((time.time() - embedding_started) * 1000)

            logger.info(f"[RAG Events] Generated {len(embeddings)} embeddings")

            self.update_state(state='PROGRESS', meta={
                'progress': 60,
                'status': 'Refreshing scope vectors in Qdrant...'
            })

            vector_store_started = time.time()
            try:
                vector_size = len(embeddings[0]) if embeddings else getattr(Config, 'RAG_VECTOR_SIZE', 384)
                if not ensure_collection(collection_name, vector_size):
                    raise RuntimeError(f'Unable to ensure collection {collection_name}')

                _delete_scope_event_vectors(qdrant_client, collection_name, scope)
            except Exception as e:
                logger.error(f"[RAG Events] Failed to prepare scope refresh: {e}")
                return {
                    'success': False,
                    'error': f'Failed to prepare scope refresh: {e}'
                }

            self.update_state(state='PROGRESS', meta={
                'progress': 80,
                'status': 'Upserting scope vectors in Qdrant...'
            })

            try:
                from qdrant_client.models import PointStruct

                points = []
                for embedding, event_data in zip(embeddings, events_data):
                    points.append(PointStruct(
                        id=_build_event_vector_point_id(case_id, scope, event_data['record_id']),
                        vector=embedding,
                        payload=event_data
                    ))

                for i in range(0, len(points), batch_size):
                    batch = points[i:i + batch_size]
                    qdrant_client.upsert(
                        collection_name=collection_name,
                        points=batch,
                        wait=True,
                    )

                logger.info(
                    f"[RAG Events] Refreshed {len(points)} event vectors in {collection_name} for scope {scope}"
                )

            except Exception as e:
                logger.error(f"[RAG Events] Failed to upsert vectors: {e}")
                return {
                    'success': False,
                    'error': f'Failed to upsert vectors: {e}'
                }
            vector_store_duration_ms = int((time.time() - vector_store_started) * 1000)

            return {
                'success': True,
                'case_id': case_id,
                'events_embedded': len(embeddings),
                'collection_name': collection_name,
                'scope': scope,
                'message': f'Embedded {len(embeddings)} events for scope {scope}',
                'benchmark': {
                    'query_duration_ms': query_duration_ms,
                    'embedding_duration_ms': embedding_duration_ms,
                    'vector_store_duration_ms': vector_store_duration_ms,
                    'total_duration_ms': int((time.time() - overall_started) * 1000),
                }
            }
    finally:
        _release_event_embedding_lock(case_id, scope, lock_owner)


@celery_app.task(name='tasks.rag_seed_builtin_patterns')
def rag_seed_builtin_patterns() -> Dict[str, Any]:
    """Seed database with built-in attack patterns"""
    from models.rag import seed_builtin_patterns
    
    app = get_flask_app()
    
    with app.app_context():
        added = seed_builtin_patterns()
        
        # Update vectors
        try:
            _update_pattern_vectors()
        except Exception as e:
            logger.warning(f"[RAG] Vector update failed: {e}")
        
        return {
            'success': True,
            'patterns_added': added
        }


@celery_app.task(bind=True, name='tasks.rag_sync_external_patterns')
def rag_sync_external_patterns(
    self,
    sources: List[str] = None,
    triggered_by: str = 'system'
) -> Dict[str, Any]:
    """
    Sync attack patterns from multiple external sources.
    
    Converts Sigma rules to executable ClickHouse queries.
    
    Args:
        sources: List of sources to sync. Options:
            - 'hayabusa': Local Hayabusa rules (already cloned for parsing)
            - 'sigma_github': SigmaHQ GitHub repository
            - 'mdecrevoisier': mdecrevoisier's curated Sigma rules
            - 'opencti_sigma': Sigma indicators from OpenCTI
            - 'car': MITRE CAR analytics
        triggered_by: Username who triggered the sync
        
    Returns:
        Dict with sync results
    """
    import os
    from utils.sigma_converter import SigmaToPatternConverter, convert_sigma_directory
    from utils.opencti import get_opencti_client
    from models.database import db
    from models.system_settings import SystemSettings, SettingKeys
    
    app = get_flask_app()
    
    # Default sources - prioritize local Hayabusa (fast) and OpenCTI
    if sources is None:
        sources = get_default_external_sync_sources()
    
    with app.app_context():
        from models.rag import AttackPattern, RAGSyncLog
        
        # Create sync log
        sync_log = RAGSyncLog(
            source='external_patterns',
            sync_type='multi_source',
            triggered_by=triggered_by
        )
        db.session.add(sync_log)
        db.session.commit()
        
        converter = SigmaToPatternConverter()
        stats = initialize_external_sync_stats()
        from utils.licensing.license_manager import LicenseManager

        hayabusa_paths = [
            '/opt/casescope/rules/hayabusa-rules/hayabusa/builtin',
            '/opt/casescope/rules/hayabusa-rules/sigma',
        ]
        sigma_dir = '/tmp/sigma_rules'
        mdec_dir = '/tmp/mdecrevoisier_sigma'
        car_dir = '/tmp/mitre_car'
        opencti_enabled = SystemSettings.get(SettingKeys.OPENCTI_ENABLED, False)
        rag_sync_enabled = SystemSettings.get(SettingKeys.OPENCTI_RAG_SYNC, False)
        source_stage_runners = build_external_sync_source_stage_runners(
            stats=stats,
            update_state=self.update_state,
            log_info=logger.info,
            log_error=logger.error,
            log_debug=logger.debug,
            converter=converter,
            get_opencti_client=get_opencti_client,
            convert_sigma_directory=convert_sigma_directory,
            save_pattern=lambda pattern: save_synced_attack_pattern(
                pattern,
                model_class=AttackPattern,
                db_session=db.session,
                last_synced_at=datetime.utcnow(),
                update_fields=SYNC_ATTACK_PATTERN_UPDATE_FIELDS,
            ),
            apply_sync_result=apply_external_source_sync_result,
            hayabusa_paths=hayabusa_paths,
            sigma_dir=sigma_dir,
            mdec_dir=mdec_dir,
            car_dir=car_dir,
            feature_activated=LicenseManager.is_feature_activated('opencti'),
            opencti_enabled=opencti_enabled,
            rag_sync_enabled=rag_sync_enabled,
        )

        for source_name in sources:
            runner = source_stage_runners.get(source_name)
            if runner is not None:
                runner()
        
        # ============================================================
        # UPDATE VECTORS
        # ============================================================
        run_pattern_vector_update_stage(
            stats=stats,
            update_state=self.update_state,
            log_info=logger.info,
            log_warning=logger.warning,
            update_vectors=_update_pattern_vectors,
        )
        
        # ============================================================
        # FINALIZE
        # ============================================================
        finalize_rag_sync_log(
            sync_log,
            patterns_added=stats['total_added'],
            patterns_updated=stats['total_updated'],
            error_message=summarize_sync_errors(stats['errors']),
        )
        db.session.commit()
        
        # Get final counts
        total_patterns = AttackPattern.query.count()
        executable_patterns = AttackPattern.query.filter(
            AttackPattern.clickhouse_query.isnot(None)
        ).count()
        
        return build_multi_source_sync_response(
            stats=stats,
            sources=sources,
            total_patterns=total_patterns,
            executable_patterns=executable_patterns,
        )
# ============================================================================
# NON-AI PATTERN DETECTION
# ============================================================================

def calculate_confidence(
    pattern: Dict[str, Any],
    event_count: int,
    host_count: int,
    duration_seconds: int,
    match_data: Dict[str, Any],
    category_matches: int
) -> tuple:
    """
    Calculate confidence score (0-100) for a pattern match.
    
    For TEMPORAL patterns:
    - Indicator Count (30%): How many supporting indicators present
    - Time Density (20%): Events per hour in attack window
    - Specificity (25%): Pattern severity + temporal complexity
    - Corroboration (25%): Other patterns in same category
    
    For SIMPLE patterns:
    - Volume (25%): Events vs threshold
    - Multi-Host (25%): Pattern across multiple hosts
    - Specificity (25%): Pattern complexity/severity
    - Corroboration (25%): Other patterns in same category
    
    Returns:
        (confidence_score, factors_breakdown)
    """
    factors = {}
    is_temporal = pattern.get('temporal', False)
    
    if is_temporal:
        # TEMPORAL PATTERN CONFIDENCE
        
        # 1. Indicator Count Factor (0-30)
        # How many supporting indicators were found
        indicator_count = 0
        for key in ['indicator_count', 'nearby_logons', 'nearby_creds', 'nearby_smb', 
                    'network_logons', 'explicit_creds', 'total_logons', 'total_smb']:
            val = match_data.get(key, 0)
            if val:
                try:
                    indicator_count += int(val) if int(val) > 0 else 0
                except:
                    pass
        
        if indicator_count >= 3:
            indicator_score = 30
        elif indicator_count >= 2:
            indicator_score = 25
        elif indicator_count >= 1:
            indicator_score = 18
        else:
            indicator_score = 10  # Only anchor matched
        
        factors['indicators'] = {
            'score': indicator_score,
            'detail': f'{indicator_count} supporting indicators found'
        }
        
        # 2. Time Density Factor (0-20)
        # Events per hour in attack window (high density = more suspicious)
        if duration_seconds and duration_seconds > 0:
            hours = max(duration_seconds / 3600, 0.1)  # Min 6 min
            events_per_hour = event_count / hours
            
            if events_per_hour >= 10:
                density_score = 20  # High burst
            elif events_per_hour >= 5:
                density_score = 15
            elif events_per_hour >= 2:
                density_score = 10
            else:
                density_score = 5  # Spread out over long time
        else:
            density_score = 15  # Unknown duration, assume moderate
        
        factors['time_density'] = {
            'score': density_score,
            'detail': f'{event_count} events in {duration_seconds or 0}s window'
        }
        
        # 3. Specificity Factor (0-25) - same as before but temporal bonus
        severity = pattern.get('severity', 'medium')
        severity_scores = {'critical': 20, 'high': 15, 'medium': 10, 'low': 5}
        specificity_score = severity_scores.get(severity, 10)
        
        # Bonus for temporal patterns (already more accurate)
        specificity_score = min(25, specificity_score + 5)
        
        factors['specificity'] = {
            'score': specificity_score,
            'detail': f'Severity: {severity}, temporal: yes'
        }
        
        # 4. Corroboration Factor (0-25)
        if category_matches >= 5:
            corr_score = 25
        elif category_matches >= 3:
            corr_score = 20
        elif category_matches >= 2:
            corr_score = 15
        else:
            corr_score = 8
        
        factors['corroboration'] = {
            'score': corr_score,
            'detail': f'{category_matches} patterns in this category'
        }
        
        total = indicator_score + density_score + specificity_score + corr_score
        
    else:
        # SIMPLE PATTERN CONFIDENCE (original logic)
        
        # 1. Volume Factor (0-25)
        thresholds = pattern.get('thresholds', {})
        min_events = thresholds.get('min_events', thresholds.get('min_logons', 1))
        
        if event_count <= min_events:
            volume_score = 10
        elif event_count <= min_events * 2:
            volume_score = 15
        elif event_count <= min_events * 5:
            volume_score = 20
        else:
            volume_score = 25
        
        factors['volume'] = {
            'score': volume_score,
            'detail': f'{event_count} events (threshold: {min_events})'
        }
        
        # 2. Multi-Host Factor (0-25)
        if host_count >= 5:
            host_score = 25
        elif host_count >= 3:
            host_score = 20
        elif host_count >= 2:
            host_score = 15
        else:
            host_score = 10
        
        factors['multi_host'] = {
            'score': host_score,
            'detail': f'{host_count} hosts affected'
        }
        
        # 3. Specificity Factor (0-25)
        severity = pattern.get('severity', 'medium')
        query = pattern.get('detection_query', '')
        severity_scores = {'critical': 20, 'high': 15, 'medium': 10, 'low': 5}
        specificity_score = severity_scores.get(severity, 10)
        
        if 'LEFT JOIN' in query or 'NOT IN' in query or 'IS NULL' in query:
            specificity_score = min(25, specificity_score + 5)
        
        factors['specificity'] = {
            'score': specificity_score,
            'detail': f'Severity: {severity}, temporal: no'
        }
        
        # 4. Corroboration Factor (0-25)
        if category_matches >= 5:
            corr_score = 25
        elif category_matches >= 3:
            corr_score = 20
        elif category_matches >= 2:
            corr_score = 15
        else:
            corr_score = 8
        
        factors['corroboration'] = {
            'score': corr_score,
            'detail': f'{category_matches} patterns in this category'
        }
        
        total = volume_score + host_score + specificity_score + corr_score
    
    # Ensure within 0-100 range
    confidence = max(0, min(100, total))
    
    return confidence, factors


@celery_app.task(bind=True, name='tasks.detect_attack_patterns')
def detect_attack_patterns(
    self,
    case_id: int,
    case_uuid: str,
    categories: List[str] = None,
    time_filter: str = None
) -> Dict[str, Any]:
    """
    Detect attack patterns using rule-based ClickHouse queries (no AI/ML).
    
    Runs predefined pattern detection queries against case events to identify
    common attack techniques like credential attacks, lateral movement,
    persistence, privilege escalation, defense evasion, discovery, and exfiltration.
    
    Args:
        case_id: PostgreSQL case.id
        case_uuid: Case UUID
        categories: Optional list of categories to scan (None = all)
        time_filter: Optional SQL clause for time filtering (e.g., "timestamp_utc >= '...'")
        
    Returns:
        Dict with detection results
    """
    from utils.clickhouse import get_fresh_client
    from models.database import db
    from models.pattern_rules import ALL_PATTERN_RULES, PATTERN_CATEGORIES
    
    app = get_flask_app()
    
    with app.app_context():
        from models.rag import PatternRuleMatch
        
        # Initialize hunting logger for this case
        hunt_log = get_hunting_logger(case_id=case_id, case_uuid=case_uuid)
        hunt_log.log_start('detect_attack_patterns', categories=categories)
        
        client = get_fresh_client()
        
        self.update_state(state='PROGRESS', meta={
            'progress': 5,
            'status': 'Initializing pattern detection...'
        })
        
        # Get event count for logging (include time filter if specified)
        try:
            time_clause = _build_time_filter_clause(time_filter)
            count_query = f"SELECT count() FROM events WHERE case_id = {{case_id:UInt32}}{time_clause}"
            count_result = client.query(
                count_query,
                parameters={'case_id': case_id}
            )
            total_events = count_result.result_rows[0][0] if count_result.result_rows else 0
            hunt_log.log_event_count(total_events)
            if time_filter:
                hunt_log.info(f"Time filter active: scanning {total_events:,} events in time range")
        except Exception as e:
            hunt_log.warning(f"Could not get event count: {e}")
            total_events = 0
        
        # Clear existing matches for this case
        PatternRuleMatch.query.filter_by(case_id=case_id).delete()
        db.session.commit()
        hunt_log.info(f"Cleared existing pattern matches for case {case_id}")
        
        # Filter patterns by category if specified
        if categories:
            patterns_to_check = [
                p for p in ALL_PATTERN_RULES 
                if p.get('category') in categories
            ]
            hunt_log.info(f"Filtering to categories: {categories}")
        else:
            patterns_to_check = ALL_PATTERN_RULES
        
        total_patterns = len(patterns_to_check)
        hunt_log.info(f"Will check {total_patterns} patterns")
        
        matches_found = []
        errors = []
        error_count = 0
        
        # Noise filter to exclude events marked as noise
        noise_filter = " AND (noise_matched = false OR noise_matched IS NULL)"
        
        # Time filter (optional) - passed from API when user selects time range
        time_filter_clause = ""
        if time_filter:
            time_filter_clause = _build_time_filter_clause(time_filter)
            hunt_log.info(f"Applying time filter: {time_filter}")
        
        for idx, pattern in enumerate(patterns_to_check):
            pattern_start_time = time.time()
            try:
                progress = int(((idx + 1) / total_patterns) * 90) + 5
                self.update_state(state='PROGRESS', meta={
                    'progress': progress,
                    'status': f'Checking: {pattern["name"]}...',
                    'matches_found': len(matches_found)
                })
                
                if not pattern.get('detection_query'):
                    hunt_log.log_pattern_skip(pattern['id'], 'No detection query defined')
                    continue
                
                # Log pattern check start
                hunt_log.log_pattern_start(
                    pattern_id=pattern['id'],
                    pattern_name=pattern['name'],
                    category=pattern.get('category'),
                    temporal=pattern.get('temporal', False)
                )
                
                # Inject noise filter and time filter into query
                # For CTE-based queries (WITH...), add filters to each FROM events WHERE clause
                # For simple queries, add before GROUP BY/ORDER BY
                combined_filter = noise_filter + time_filter_clause
                query_with_filters = pattern['detection_query']
                
                if 'WITH' in query_with_filters.upper() and 'FROM events' in query_with_filters:
                    # CTE-based query: add filters after each "FROM events WHERE" clause
                    # This handles temporal patterns correctly
                    
                    # Match "FROM events WHERE case_id = {case_id:UInt32}" and add filters
                    query_with_filters = re.sub(
                        r'(FROM events\s+WHERE\s+case_id\s*=\s*\{case_id:UInt32\})',
                        r'\1' + combined_filter,
                        query_with_filters,
                        flags=re.IGNORECASE
                    )
                else:
                    # Simple query: add before GROUP BY, HAVING, ORDER BY, or LIMIT
                    for keyword in ['GROUP BY', 'HAVING', 'ORDER BY', 'LIMIT']:
                        match = re.search(keyword, query_with_filters, re.IGNORECASE)
                        if match:
                            pos = match.start()
                            query_with_filters = query_with_filters[:pos] + combined_filter + ' ' + query_with_filters[pos:]
                            break
                    else:
                        query_with_filters = query_with_filters.rstrip() + combined_filter
                
                # Run detection query with timing
                query_start = time.time()
                result = client.query(
                    query_with_filters,
                    parameters={'case_id': case_id}
                )
                query_time_ms = (time.time() - query_start) * 1000
                
                # Log query execution
                hunt_log.log_pattern_query(
                    pattern_id=pattern['id'],
                    query_time_ms=query_time_ms,
                    rows_returned=len(result.result_rows) if result.result_rows else 0,
                    query_preview=query_with_filters[:200] if query_time_ms > 500 else None
                )
                
                if result.result_rows:
                    for row in result.result_rows:
                        # Convert row to dict
                        row_dict = {}
                        if result.column_names:
                            for i, col in enumerate(result.column_names):
                                if i < len(row):
                                    row_dict[col] = row[i]
                        
                        # Extract common fields
                        source_host = (
                            row_dict.get('source_host') or 
                            (row_dict.get('source_hosts', [None])[0] if row_dict.get('source_hosts') else None)
                        )
                        username = (
                            row_dict.get('username') or
                            (row_dict.get('usernames', [None])[0] if row_dict.get('usernames') else None)
                        )
                        affected_users = (
                            list(row_dict['usernames']) if row_dict.get('usernames') else
                            ([row_dict['username']] if row_dict.get('username') else None)
                        )
                        
                        # Extract timestamps
                        first_seen = None
                        for ts_field in ['first_fail', 'first_seen', 'first_access', 'first_activity']:
                            if row_dict.get(ts_field):
                                first_seen = row_dict[ts_field]
                                break
                        
                        last_seen = None
                        for ts_field in ['last_fail', 'last_seen', 'last_access', 'last_activity']:
                            if row_dict.get(ts_field):
                                last_seen = row_dict[ts_field]
                                break
                        
                        # Extract event count
                        event_count = 1
                        for count_field in ['total_failures', 'fail_count', 'logon_count', 'event_count',
                                           'tgs_requests', 'tgt_requests', 'dump_events', 'service_events',
                                           'wmi_events', 'task_events', 'registry_events', 'enum_events',
                                           'ad_events', 'bloodhound_events', 'staging_events', 'dns_events',
                                           'cloud_events', 'clear_events', 'stomp_events', 'injection_events',
                                           'amsi_events', 'token_events', 'pipe_events', 'uac_bypass_events',
                                           'wmi_persistence_events', 'unique_users', 'hosts_accessed']:
                            if row_dict.get(count_field):
                                event_count = int(row_dict[count_field])
                                break
                        
                        # Calculate duration
                        duration_seconds = None
                        if row_dict.get('duration_secs'):
                            duration_seconds = int(row_dict['duration_secs'])
                        elif first_seen and last_seen:
                            try:
                                duration_seconds = int((last_seen - first_seen).total_seconds())
                            except:
                                pass
                        
                        # Calculate duration in minutes for logging
                        duration_minutes = None
                        if duration_seconds:
                            duration_minutes = duration_seconds / 60
                        
                        # Store match data for later confidence calculation
                        matches_found.append({
                            'pattern': pattern,
                            'pattern_id': pattern['id'],
                            'pattern_name': pattern['name'],
                            'category': pattern['category'],
                            'severity': pattern.get('severity', 'medium'),
                            'source_host': source_host,
                            'username': username,
                            'affected_users': affected_users[:20] if affected_users else None,
                            'event_count': event_count,
                            'first_seen': first_seen if isinstance(first_seen, datetime) else None,
                            'last_seen': last_seen if isinstance(last_seen, datetime) else None,
                            'duration_seconds': duration_seconds,
                            'match_data': {k: str(v)[:500] for k, v in row_dict.items()}
                        })
                
                # Log pattern completion
                pattern_time_ms = (time.time() - pattern_start_time) * 1000
                hunt_log.log_pattern_complete(
                    pattern_id=pattern['id'],
                    matches=len(result.result_rows) if result.result_rows else 0,
                    query_time_ms=pattern_time_ms
                )
                        
            except Exception as e:
                error_count += 1
                logger.warning(f"[PatternRules] Pattern {pattern['name']} failed: {e}")
                hunt_log.log_pattern_error(pattern['id'], str(e))
                errors.append(f"{pattern['name']}: {str(e)[:100]}")
        
        # Calculate category counts for corroboration factor
        category_counts = {}
        for match in matches_found:
            cat = match['category']
            category_counts[cat] = category_counts.get(cat, 0) + 1
        
        hunt_log.log_category_summary(category_counts)
        
        # Now create match records with confidence scores
        hunt_log.info(f"Saving {len(matches_found)} matches to database...")
        
        for match_info in matches_found:
            pattern = match_info['pattern']
            category = match_info['category']
            
            # Calculate confidence
            confidence, confidence_factors = calculate_confidence(
                pattern=pattern,
                event_count=match_info['event_count'],
                host_count=1,  # Will be aggregated in results API
                duration_seconds=match_info['duration_seconds'] or 0,
                match_data=match_info['match_data'],
                category_matches=category_counts.get(category, 1)
            )
            
            # Log match with confidence
            hunt_log.log_match(
                pattern_id=match_info['pattern_id'],
                pattern_name=match_info['pattern_name'],
                source_host=match_info['source_host'],
                username=match_info['username'],
                confidence=confidence,
                event_count=match_info['event_count'],
                first_seen=match_info['first_seen'],
                last_seen=match_info['last_seen'],
                duration_minutes=match_info['duration_seconds'] / 60 if match_info['duration_seconds'] else None
            )
            
            # Log confidence calculation details
            hunt_log.log_confidence_calc(
                pattern_id=match_info['pattern_id'],
                confidence=confidence,
                factors=confidence_factors
            )
            
            match = PatternRuleMatch(
                case_id=case_id,
                pattern_id=match_info['pattern_id'],
                pattern_name=match_info['pattern_name'],
                category=category,
                description=pattern.get('description'),
                severity=match_info['severity'],
                mitre_tactics=pattern.get('mitre_tactics'),
                mitre_techniques=pattern.get('mitre_techniques'),
                source_host=match_info['source_host'],
                username=match_info['username'],
                affected_users=match_info['affected_users'],
                event_count=match_info['event_count'],
                first_seen=match_info['first_seen'],
                last_seen=match_info['last_seen'],
                duration_seconds=match_info['duration_seconds'],
                match_data=match_info['match_data'],
                indicators=pattern.get('indicators', []),
                confidence=confidence,
                confidence_factors=confidence_factors
            )
            db.session.add(match)
        
        db.session.commit()
        
        self.update_state(state='PROGRESS', meta={
            'progress': 100,
            'status': 'Complete',
            'matches_found': len(matches_found)
        })
        
        # Log completion
        hunt_log.log_complete(
            patterns_checked=len(patterns_to_check),
            matches_found=len(matches_found),
            errors=error_count,
            total_events=total_events
        )
        
        return {
            'success': True,
            'case_id': case_id,
            'case_uuid': case_uuid,
            'patterns_checked': len(patterns_to_check),
            'matches_found': len(matches_found),
            'categories_matched': category_counts,
            'matches': matches_found[:50],  # Limit response size
            'errors': errors[:10] if errors else None,
            'log_file': hunt_log.get_log_path()
        }


@celery_app.task(bind=True, name='tasks.ai_pattern_correlation')
def ai_pattern_correlation(
    self,
    case_id: int,
    case_uuid: str,
    patterns: List[str] = None,
    time_start: str = None,
    time_end: str = None
) -> Dict[str, Any]:
    """AI-powered pattern correlation pipeline
    
    Uses DeepSeek-R1 LLM to analyze candidate events and determine
    if they constitute true attack pattern matches.
    
    Pipeline stages:
    1. Extract candidate events from ClickHouse
    2. Tag with roles (anchor/supporting/context)
    3. Run AI analysis with pattern checklists
    4. Blend rule-based and AI confidence scores
    5. Store results
    
    Args:
        case_id: PostgreSQL case ID
        case_uuid: Case UUID for logging
        patterns: List of pattern IDs to analyze (None = all)
        time_start: ISO format start time filter
        time_end: ISO format end time filter
        
    Returns:
        Dict with analysis results and statistics
    """
    import uuid as uuid_module
    from datetime import datetime
    from pipeline.pattern_analysis import (
        apply_pattern_suppression,
        select_highest_scoring_packages,
    )
    from utils.candidate_extractor import CandidateExtractor
    from utils.ai_correlation_analyzer import AICorrelationAnalyzer
    from utils.feature_availability import FeatureAvailability
    from utils.pattern_event_mappings import get_all_patterns, get_patterns_by_ids
    
    app = get_flask_app()
    
    with app.app_context():
        from models.database import db
        from models.case import Case
        
        hunt_log = get_hunting_logger(case_id)
        hunt_log.log_start('ai_pattern_correlation', patterns=patterns)
        
        self.update_state(state='PROGRESS', meta={
            'progress': 5,
            'status': 'Initializing AI correlation pipeline',
            'stage': 'init'
        })

        if not FeatureAvailability.is_ai_enabled():
            hunt_log.log_error('ai_pattern_correlation', 'AI features are not currently available')
            return {
                'success': False,
                'error': 'AI features are not currently available',
                'case_id': case_id
            }
        
        # Parse time filters
        start_dt = None
        end_dt = None
        if time_start:
            try:
                start_dt = datetime.fromisoformat(time_start)
            except ValueError:
                pass
        if time_end:
            try:
                end_dt = datetime.fromisoformat(time_end)
            except ValueError:
                pass
        
        # Get patterns to analyze
        if patterns:
            pattern_configs = get_patterns_by_ids(patterns)
        else:
            pattern_configs = get_all_patterns()
        
        if not pattern_configs:
            return {
                'success': False,
                'error': 'No valid patterns to analyze',
                'case_id': case_id
            }
        
        logger.info(f"[AI Correlation] Starting analysis for {len(pattern_configs)} patterns on case {case_id}")
        
        analysis_id = str(uuid_module.uuid4())
        extractor = CandidateExtractor(case_id, analysis_id)
        
        from utils.deterministic_evidence_engine import DeterministicEvidenceEngine
        from models.rag import AIAnalysisResult
        
        census = {}
        try:
            from utils.clickhouse import get_fresh_client
            ch = get_fresh_client()
            census_result = ch.query(
                "SELECT event_id, count() as cnt FROM events "
                "WHERE case_id = {case_id:UInt32} "
                "AND (noise_matched = false OR noise_matched IS NULL) "
                "GROUP BY event_id",
                parameters={'case_id': case_id}
            )
            census = {str(row[0]): int(row[1]) for row in census_result.result_rows}
        except Exception as e:
            logger.warning(f"[AI Correlation] Census query failed: {e}")
        
        evidence_engine = DeterministicEvidenceEngine(
            case_id=case_id,
            analysis_id=analysis_id,
            census=census,
            gap_findings=[],
        )
        
        ai_analyzer = AICorrelationAnalyzer(
            case_id=case_id,
            analysis_id=analysis_id
        )
        
        # OpenCTI for threat intel context in AI prompts
        opencti_provider = None
        try:
            from utils.opencti_context import OpenCTIContextProvider
            _provider = OpenCTIContextProvider(case_id, analysis_id)
            if _provider.is_available():
                opencti_provider = _provider
        except Exception:
            pass
        
        all_results = []
        extraction_stats = {}
        analysis_stats = {}
        errors = []
        
        ordered_patterns = sorted(
            pattern_configs.items(),
            key=lambda item: (
                PATTERN_SUPPRESSION_PRIORITY.get(item[0], 999),
                item[1].get('name', item[0]),
            ),
        )
        total_patterns = len(ordered_patterns)
        confirmed_patterns = {}
        
        for idx, (pattern_id, pattern_config) in enumerate(ordered_patterns):
            progress = 10 + int((idx / total_patterns) * 80)
            
            self.update_state(state='PROGRESS', meta={
                'progress': progress,
                'status': f'Analyzing {pattern_config["name"]}',
                'stage': 'analysis',
                'pattern': pattern_id,
                'pattern_index': idx + 1,
                'total_patterns': total_patterns
            })
            
            try:
                extraction_result = extractor.extract_pattern_candidates(
                    pattern_config=pattern_config,
                    time_start=start_dt,
                    time_end=end_dt
                )
                
                extraction_stats[pattern_id] = {
                    'anchor_count': extraction_result['anchor_count'],
                    'supporting_count': extraction_result['supporting_count'],
                    'total_stored': extraction_result['total_stored']
                }
                
                if extraction_result['total_stored'] == 0:
                    logger.info(f"[AI Correlation] No candidates for {pattern_id}, skipping")
                    continue
                
                anchor_events = extraction_result.get('anchors', [])
                time_window = pattern_config.get('time_window_minutes', 60)
                
                evidence_packages = evidence_engine.evaluate_pattern(
                    pattern_id, pattern_config, anchor_events, time_window
                )
                
                ai_full_threshold = pattern_config.get('ai_full_threshold', 40)
                ai_gray_threshold = pattern_config.get('ai_gray_threshold', 20)
                evidence_packages = select_highest_scoring_packages(evidence_packages)
                
                # Build threat intel context for this pattern (500 char budget)
                ti_context = ""
                if opencti_provider:
                    try:
                        mitre_ids = pattern_config.get('mitre_techniques', [])
                        ti_parts = []
                        for mid in mitre_ids[:2]:
                            ctx = opencti_provider.get_attack_pattern_context(mid)
                            if ctx.get('technique_name'):
                                actors = [a['name'] for a in ctx.get('threat_actors', [])[:3]]
                                if actors:
                                    ti_parts.append(f"THREAT INTEL: {mid} is used by {', '.join(actors)}.")
                                det = ctx.get('detection_guidance')
                                if det:
                                    ti_parts.append(f"Detection guidance: {det[:150]}")
                        if ti_parts:
                            ti_context = "\n".join(ti_parts)[:500]
                            ti_context += ("\nNote: use 'consistent with' language, "
                                          "not definitive attribution.")
                    except Exception:
                        ti_context = ""
                
                pattern_confirmed = []
                for pkg in evidence_packages:
                    suppression_result = apply_pattern_suppression(
                        pattern_id,
                        pkg,
                        confirmed_patterns,
                    )
                    if suppression_result['suppressed']:
                        logger.info(
                            f"[AI Correlation] Suppressing {pattern_id}:{pkg.correlation_key} - "
                            f"superseded by {suppression_result['suppressor']}"
                        )
                        continue

                    soft_adjustment = suppression_result['soft_adjustment']
                    if soft_adjustment:
                        logger.info(
                            f"[AI Correlation] Down-ranking {pattern_id}:{pkg.correlation_key} by "
                            f"{soft_adjustment} due to overlapping higher-specificity pattern(s)"
                        )

                    finalized = finalize_deterministic_package(
                        pkg,
                        ai_full_threshold=ai_full_threshold,
                        ai_gray_threshold=ai_gray_threshold,
                        run_full_analysis=lambda: ai_analyzer.analyze_with_evidence(
                            pkg, pattern_config, threat_intel_context=ti_context
                        ),
                        run_light_analysis=lambda: ai_analyzer.analyze_with_evidence_lightweight(pkg, pattern_config),
                    )
                    final_score = finalized['final_score']
                    ai_adj = finalized['ai_adjustment']
                    evidence_package = finalized['evidence_package']
                    artifacts = build_deterministic_analysis_artifacts(
                        case_id=case_id,
                        analysis_id=analysis_id,
                        source_system='ai_correlation',
                        pattern_id=pattern_id,
                        pattern_name=pattern_config['name'],
                        correlation_key=pkg.correlation_key,
                        confidence=final_score,
                        summary=f"Pattern match: {pattern_config['name']} ({pkg.correlation_key})",
                        evidence_package=evidence_package,
                        severity=severity_from_confidence(final_score),
                        events_analyzed=extraction_result.get('anchor_count', 0),
                        deterministic_score=pkg.deterministic_score,
                        coverage_quality=pkg.coverage.coverage_score if pkg.coverage else None,
                        ai_adjustment=ai_adj,
                        ai_escalated=pkg.ai_escalated,
                        ai_reasoning=finalized['ai_reasoning'],
                        ai_false_positive_assessment=finalized['ai_false_positive_assessment'],
                        mitre_techniques=pattern_config.get('mitre_techniques', []),
                        rule_based_confidence=extraction_result.get('base_confidence', 50),
                        model_used=ai_analyzer.model if pkg.ai_judgment else 'deterministic',
                    )
                    
                    result_record = AIAnalysisResult(**artifacts['analysis_result_payload'])
                    db.session.add(result_record)
                    
                    if finalized['should_emit_finding']:
                        all_results.append(artifacts['finding'])
                    pattern_confirmed.append(
                        build_confirmed_pattern_entry(
                            correlation_key=pkg.correlation_key,
                            score=final_score,
                            anchor=pkg.anchor,
                        )
                    )
                
                db.session.commit()
                if should_track_pattern_for_suppression(pattern_id):
                    confirmed_patterns[pattern_id] = pattern_confirmed
                analysis_stats[pattern_id] = ai_analyzer.get_stats()
                
            except Exception as e:
                logger.error(f"[AI Correlation] Error analyzing {pattern_id}: {e}")
                errors.append({
                    'pattern_id': pattern_id,
                    'error': str(e)
                })
        
        try:
            extractor.cleanup()
        except Exception as e:
            logger.warning(f"[AI Correlation] Cleanup error: {e}")
        
        all_results.sort(key=lambda x: x['confidence'], reverse=True)
        
        _OVERLAP_PAIRS = [
            ('lsass_memory_dump', 'process_injection'),
            ('lsass_memory_dump', 'powershell_credential_dump'),
        ]
        detected_ids = {r['pattern_id'] for r in all_results}
        for result in all_results:
            overlaps = []
            for a, b in _OVERLAP_PAIRS:
                if result['pattern_id'] == a and b in detected_ids:
                    overlaps.append(b)
                elif result['pattern_id'] == b and a in detected_ids:
                    overlaps.append(a)
            if overlaps:
                result['overlapping_patterns'] = overlaps
        
        self.update_state(state='PROGRESS', meta={
            'progress': 100,
            'status': 'Complete',
            'stage': 'complete',
            'results_count': len(all_results)
        })
        
        hunt_log.log_complete(
            patterns_checked=len(pattern_configs),
            matches_found=len(all_results),
            errors=len(errors)
        )
        
        return {
            'success': True,
            'case_id': case_id,
            'case_uuid': case_uuid,
            'analysis_id': analysis_id,
            'patterns_analyzed': len(pattern_configs),
            'results_count': len(all_results),
            'high_confidence_count': len([r for r in all_results if r['confidence'] >= 70]),
            'results': all_results[:100],  # Limit response size
            'extraction_stats': extraction_stats,
            'errors': errors if errors else None
        }
