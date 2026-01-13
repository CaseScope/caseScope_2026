"""RAG Tasks for CaseScope - Pattern Discovery and Timeline Generation

Provides Celery tasks for:
- Pattern discovery across case events
- Related event hunting
- Timeline generation
- OpenCTI pattern sync
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

from tasks.celery_tasks import celery_app, get_flask_app

logger = logging.getLogger(__name__)


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
    
    app = get_flask_app()
    
    with app.app_context():
        from models.rag import AttackPattern, RAGSyncLog
        
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
            sync_log.success = False
            sync_log.error_message = 'OpenCTI not configured or disabled'
            sync_log.completed_at = datetime.utcnow()
            db.session.commit()
            return {'success': False, 'error': 'OpenCTI not configured'}
        
        if client.init_error:
            sync_log.success = False
            sync_log.error_message = client.init_error
            sync_log.completed_at = datetime.utcnow()
            db.session.commit()
            return {'success': False, 'error': client.init_error}
        
        stats = {'attack_patterns': 0, 'indicators': 0, 'updated': 0}
        
        self.update_state(state='PROGRESS', meta={'stage': 'attack_patterns', 'progress': 10})
        
        # Sync Attack Patterns
        try:
            patterns = client.get_attack_patterns(limit=500)
            
            for pattern in patterns:
                if not pattern.get('mitre_id'):
                    continue
                
                existing = AttackPattern.query.filter_by(
                    source='opencti',
                    source_id=pattern['opencti_id']
                ).first()
                
                if existing:
                    existing.description = pattern.get('detection') or pattern.get('description')
                    existing.last_synced_at = datetime.utcnow()
                    stats['updated'] += 1
                else:
                    tactic = pattern['kill_chain_phases'][0] if pattern['kill_chain_phases'] else None
                    new_pattern = AttackPattern(
                        name=pattern['name'],
                        description=pattern.get('detection') or pattern.get('description'),
                        mitre_tactic=tactic,
                        mitre_technique=pattern['mitre_id'],
                        source='opencti',
                        source_id=pattern['opencti_id'],
                        pattern_type='single',
                        pattern_definition={
                            'type': 'mitre_technique',
                            'platforms': pattern.get('platforms', []),
                        },
                        required_artifact_types=['evtx'],
                        last_synced_at=datetime.utcnow(),
                        created_by='opencti_sync'
                    )
                    db.session.add(new_pattern)
                    stats['attack_patterns'] += 1
        except Exception as e:
            logger.error(f"[RAG] Error syncing attack patterns: {e}")
        
        self.update_state(state='PROGRESS', meta={'stage': 'indicators', 'progress': 50})
        
        # Sync Indicators with Sigma patterns
        try:
            indicators = client.get_indicators_with_patterns(limit=500)
            
            for ind in indicators:
                if ind.get('pattern_type') != 'sigma' or not ind.get('pattern'):
                    continue
                
                existing = AttackPattern.query.filter_by(
                    source='opencti_sigma',
                    source_id=ind['opencti_id']
                ).first()
                
                if not existing:
                    tactic = ind['kill_chain_phases'][0] if ind['kill_chain_phases'] else None
                    new_pattern = AttackPattern(
                        name=ind['name'],
                        source='opencti_sigma',
                        source_id=ind['opencti_id'],
                        pattern_type='sigma',
                        pattern_definition={
                            'type': 'sigma',
                            'raw_pattern': ind['pattern'],
                            'score': ind.get('score', 0),
                        },
                        mitre_tactic=tactic,
                        last_synced_at=datetime.utcnow(),
                        created_by='opencti_sync'
                    )
                    db.session.add(new_pattern)
                    stats['indicators'] += 1
        except Exception as e:
            logger.error(f"[RAG] Error syncing indicators: {e}")
        
        db.session.commit()
        
        # Update sync log
        sync_log.patterns_added = stats['attack_patterns'] + stats['indicators']
        sync_log.patterns_updated = stats['updated']
        sync_log.success = True
        sync_log.completed_at = datetime.utcnow()
        db.session.commit()
        
        # Update vector store
        self.update_state(state='PROGRESS', meta={'stage': 'vectorizing', 'progress': 80})
        try:
            _update_pattern_vectors()
        except Exception as e:
            logger.warning(f"[RAG] Vector update failed: {e}")
        
        return {
            'success': True,
            'synced': stats,
            'message': f"Synced {stats['attack_patterns']} patterns, {stats['indicators']} indicators, updated {stats['updated']}"
        }


@celery_app.task(bind=True, name='tasks.rag_discover_patterns')
def rag_discover_patterns(
    self,
    case_id: int,
    case_uuid: str,
    pattern_ids: List[int] = None
) -> Dict[str, Any]:
    """
    Scan case events for matching attack patterns
    
    Uses SQL-based pattern matching for efficiency with large datasets.
    
    Args:
        case_id: PostgreSQL case.id (used as ClickHouse case_id)
        case_uuid: Case UUID
        pattern_ids: Optional list of specific pattern IDs to check
        
    Returns:
        Dict with discovery results
    """
    from utils.clickhouse import get_fresh_client
    from models.database import db
    
    app = get_flask_app()
    
    with app.app_context():
        from models.rag import AttackPattern, PatternMatch
        
        client = get_fresh_client()
        
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
        
        # Get patterns to check
        if pattern_ids:
            patterns = AttackPattern.query.filter(
                AttackPattern.id.in_(pattern_ids),
                AttackPattern.enabled == True
            ).all()
        else:
            patterns = AttackPattern.query.filter_by(enabled=True).all()
        
        # Filter to patterns with ClickHouse queries
        executable_patterns = [p for p in patterns if p.clickhouse_query]
        
        matches_found = []
        errors = []
        
        for idx, pattern in enumerate(executable_patterns):
            try:
                # Execute pattern query
                query = pattern.clickhouse_query.format(case_id=case_id)
                # Handle parameterized query
                if '{case_id:UInt32}' in pattern.clickhouse_query:
                    result = client.query(
                        pattern.clickhouse_query,
                        parameters={'case_id': case_id}
                    )
                else:
                    result = client.query(query)
                
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
            'errors': errors[:10] if errors else None
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


def _update_pattern_vectors():
    """Update vector embeddings for all patterns"""
    from models.rag import AttackPattern
    from utils.rag_embeddings import embed_pattern
    from utils.rag_vectorstore import upsert_patterns
    
    app = get_flask_app()
    
    with app.app_context():
        patterns = AttackPattern.query.filter_by(enabled=True).all()
        
        vectors = []
        for pattern in patterns:
            try:
                embedding = embed_pattern(pattern)
                vectors.append({
                    'id': pattern.id,
                    'embedding': embedding,
                    'payload': {
                        'name': pattern.name,
                        'mitre_technique': pattern.mitre_technique,
                        'source': pattern.source
                    }
                })
            except Exception as e:
                logger.warning(f"[RAG] Failed to embed pattern {pattern.id}: {e}")
        
        if vectors:
            upsert_patterns(vectors)
            logger.info(f"[RAG] Updated {len(vectors)} pattern vectors")


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
