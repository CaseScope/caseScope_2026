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
                    # Use ClickHouse parameterized query
                    result = client.query(
                        query_with_noise,
                        parameters={'case_id': case_id}
                    )
                else:
                    # Use Python string formatting for legacy queries
                    query = query_with_noise.format(case_id=case_id)
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
        
        client = get_fresh_client()
        
        self.update_state(state='PROGRESS', meta={
            'progress': 5,
            'status': 'Initializing campaign detection...'
        })
        
        # Clear existing campaigns for this case (will regenerate)
        AttackCampaign.query.filter_by(case_id=case_id).delete()
        db.session.commit()
        
        campaigns_detected = []
        errors = []
        
        total_templates = len(CAMPAIGN_TEMPLATES)
        
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
                                
            except Exception as e:
                logger.warning(f"[RAG] Campaign detection failed for {template['type']}: {e}")
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
    import subprocess
    from utils.sigma_converter import SigmaToPatternConverter, convert_sigma_directory
    from utils.opencti import get_opencti_client
    from models.database import db
    from models.system_settings import SystemSettings, SettingKeys
    
    app = get_flask_app()
    
    # Default sources - prioritize local Hayabusa (fast) and OpenCTI
    if sources is None:
        sources = ['hayabusa', 'opencti_sigma']
    
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
        stats = {
            'hayabusa': 0,
            'sigma_github': 0,
            'mdecrevoisier': 0,
            'opencti_sigma': 0,
            'car': 0,
            'total_added': 0,
            'total_updated': 0,
            'errors': []
        }
        
        total_sources = len(sources)
        
        # ============================================================
        # 1. HAYABUSA RULES (Local - fastest)
        # ============================================================
        if 'hayabusa' in sources:
            self.update_state(state='PROGRESS', meta={
                'stage': 'hayabusa',
                'progress': 10,
                'status': 'Processing Hayabusa rules...'
            })
            
            hayabusa_paths = [
                '/opt/casescope/rules/hayabusa-rules/hayabusa/builtin',
                '/opt/casescope/rules/hayabusa-rules/sigma',
            ]
            
            for rule_path in hayabusa_paths:
                if os.path.exists(rule_path):
                    try:
                        patterns = convert_sigma_directory(rule_path, source='hayabusa')
                        for pattern in patterns:
                            added = _save_pattern(pattern)
                            if added:
                                stats['hayabusa'] += 1
                                stats['total_added'] += 1
                            else:
                                stats['total_updated'] += 1
                    except Exception as e:
                        stats['errors'].append(f"Hayabusa: {str(e)[:100]}")
                        logger.error(f"[RAG] Hayabusa sync error: {e}")
            
            logger.info(f"[RAG] Hayabusa: Added {stats['hayabusa']} patterns")
        
        # ============================================================
        # 2. SIGMAHQ GITHUB (Clone if needed)
        # ============================================================
        if 'sigma_github' in sources:
            self.update_state(state='PROGRESS', meta={
                'stage': 'sigma_github',
                'progress': 30,
                'status': 'Syncing SigmaHQ rules from GitHub...'
            })
            
            sigma_dir = '/tmp/sigma_rules'
            
            try:
                # Clone or update
                if os.path.exists(sigma_dir):
                    subprocess.run(
                        ['git', '-C', sigma_dir, 'pull', '--ff-only'],
                        check=True, capture_output=True, timeout=120
                    )
                else:
                    subprocess.run([
                        'git', 'clone', '--depth', '1',
                        'https://github.com/SigmaHQ/sigma.git',
                        sigma_dir
                    ], check=True, capture_output=True, timeout=300)
                
                # Process Windows Security rules (most relevant)
                rules_paths = [
                    f"{sigma_dir}/rules/windows/builtin/security",
                    f"{sigma_dir}/rules/windows/builtin/system",
                    f"{sigma_dir}/rules/windows/process_creation",
                    f"{sigma_dir}/rules/windows/powershell",
                ]
                
                for rules_path in rules_paths:
                    if os.path.exists(rules_path):
                        patterns = convert_sigma_directory(rules_path, source='sigma_github')
                        for pattern in patterns:
                            added = _save_pattern(pattern)
                            if added:
                                stats['sigma_github'] += 1
                                stats['total_added'] += 1
                            else:
                                stats['total_updated'] += 1
                
                logger.info(f"[RAG] SigmaHQ: Added {stats['sigma_github']} patterns")
                
            except subprocess.TimeoutExpired:
                stats['errors'].append("SigmaHQ: Git clone timed out")
            except Exception as e:
                stats['errors'].append(f"SigmaHQ: {str(e)[:100]}")
                logger.error(f"[RAG] SigmaHQ sync error: {e}")
        
        # ============================================================
        # 3. MDECREVOISIER RULES
        # ============================================================
        if 'mdecrevoisier' in sources:
            self.update_state(state='PROGRESS', meta={
                'stage': 'mdecrevoisier',
                'progress': 50,
                'status': 'Syncing mdecrevoisier rules...'
            })
            
            mdec_dir = '/tmp/mdecrevoisier_sigma'
            
            try:
                if os.path.exists(mdec_dir):
                    subprocess.run(
                        ['git', '-C', mdec_dir, 'pull', '--ff-only'],
                        check=True, capture_output=True, timeout=120
                    )
                else:
                    subprocess.run([
                        'git', 'clone', '--depth', '1',
                        'https://github.com/mdecrevoisier/SIGMA-detection-rules.git',
                        mdec_dir
                    ], check=True, capture_output=True, timeout=300)
                
                # Process all rules
                if os.path.exists(mdec_dir):
                    patterns = convert_sigma_directory(mdec_dir, source='mdecrevoisier')
                    for pattern in patterns:
                        added = _save_pattern(pattern)
                        if added:
                            stats['mdecrevoisier'] += 1
                            stats['total_added'] += 1
                        else:
                            stats['total_updated'] += 1
                
                logger.info(f"[RAG] mdecrevoisier: Added {stats['mdecrevoisier']} patterns")
                
            except Exception as e:
                stats['errors'].append(f"mdecrevoisier: {str(e)[:100]}")
                logger.error(f"[RAG] mdecrevoisier sync error: {e}")
        
        # ============================================================
        # 4. OPENCTI SIGMA INDICATORS
        # ============================================================
        if 'opencti_sigma' in sources:
            self.update_state(state='PROGRESS', meta={
                'stage': 'opencti_sigma',
                'progress': 70,
                'status': 'Syncing Sigma indicators from OpenCTI...'
            })
            
            opencti_enabled = SystemSettings.get(SettingKeys.OPENCTI_ENABLED, False)
            rag_sync_enabled = SystemSettings.get(SettingKeys.OPENCTI_RAG_SYNC, False)
            
            if opencti_enabled and rag_sync_enabled:
                try:
                    client = get_opencti_client()
                    if client and not client.init_error:
                        sigma_indicators = client.get_sigma_indicators(limit=500)
                        
                        for ind in sigma_indicators:
                            try:
                                pattern = converter.convert_sigma_rule(
                                    ind['sigma_rule'],
                                    source='opencti_sigma'
                                )
                                if pattern and pattern.get('required_event_ids'):
                                    pattern['source_id'] = ind['opencti_id']
                                    added = _save_pattern(pattern)
                                    if added:
                                        stats['opencti_sigma'] += 1
                                        stats['total_added'] += 1
                                    else:
                                        stats['total_updated'] += 1
                            except Exception as e:
                                logger.debug(f"[RAG] OpenCTI indicator conversion failed: {e}")
                        
                        logger.info(f"[RAG] OpenCTI Sigma: Added {stats['opencti_sigma']} patterns")
                    else:
                        stats['errors'].append("OpenCTI: Client not available")
                except Exception as e:
                    stats['errors'].append(f"OpenCTI: {str(e)[:100]}")
                    logger.error(f"[RAG] OpenCTI Sigma sync error: {e}")
            else:
                logger.info("[RAG] OpenCTI Sigma sync skipped - not enabled")
        
        # ============================================================
        # 5. MITRE CAR
        # ============================================================
        if 'car' in sources:
            self.update_state(state='PROGRESS', meta={
                'stage': 'car',
                'progress': 85,
                'status': 'Syncing MITRE CAR analytics...'
            })
            
            car_dir = '/tmp/mitre_car'
            
            try:
                if os.path.exists(car_dir):
                    subprocess.run(
                        ['git', '-C', car_dir, 'pull', '--ff-only'],
                        check=True, capture_output=True, timeout=120
                    )
                else:
                    subprocess.run([
                        'git', 'clone', '--depth', '1',
                        'https://github.com/mitre-attack/car.git',
                        car_dir
                    ], check=True, capture_output=True, timeout=300)
                
                # CAR analytics are in analytics/ directory as YAML
                analytics_path = f"{car_dir}/analytics"
                if os.path.exists(analytics_path):
                    patterns = convert_sigma_directory(analytics_path, source='mitre_car')
                    for pattern in patterns:
                        added = _save_pattern(pattern)
                        if added:
                            stats['car'] += 1
                            stats['total_added'] += 1
                        else:
                            stats['total_updated'] += 1
                
                logger.info(f"[RAG] MITRE CAR: Added {stats['car']} patterns")
                
            except Exception as e:
                stats['errors'].append(f"MITRE CAR: {str(e)[:100]}")
                logger.error(f"[RAG] MITRE CAR sync error: {e}")
        
        # ============================================================
        # UPDATE VECTORS
        # ============================================================
        self.update_state(state='PROGRESS', meta={
            'stage': 'vectorizing',
            'progress': 95,
            'status': 'Updating vector embeddings...'
        })
        
        try:
            _update_pattern_vectors()
        except Exception as e:
            stats['errors'].append(f"Vector update: {str(e)[:100]}")
            logger.warning(f"[RAG] Vector update failed: {e}")
        
        # ============================================================
        # FINALIZE
        # ============================================================
        sync_log.patterns_added = stats['total_added']
        sync_log.patterns_updated = stats['total_updated']
        sync_log.success = True
        sync_log.completed_at = datetime.utcnow()
        if stats['errors']:
            sync_log.error_message = '; '.join(stats['errors'][:5])
        db.session.commit()
        
        # Get final counts
        total_patterns = AttackPattern.query.count()
        executable_patterns = AttackPattern.query.filter(
            AttackPattern.clickhouse_query.isnot(None)
        ).count()
        
        return {
            'success': True,
            'sources_synced': sources,
            'stats': stats,
            'total_patterns': total_patterns,
            'executable_patterns': executable_patterns,
            'message': f"Synced {stats['total_added']} new patterns from {len(sources)} sources"
        }


def _save_pattern(pattern: Dict[str, Any]) -> bool:
    """
    Save or update a pattern in the database.
    
    Args:
        pattern: Pattern dictionary from converter
        
    Returns:
        True if new pattern was added, False if updated existing
    """
    from models.rag import AttackPattern
    from models.database import db
    
    # Check for existing pattern by name and source
    existing = AttackPattern.query.filter_by(
        name=pattern['name'],
        source=pattern.get('source', 'unknown')
    ).first()
    
    if existing:
        # Update existing pattern
        for key in ['description', 'clickhouse_query', 'pattern_definition', 
                    'mitre_tactic', 'mitre_technique', 'severity', 'confidence_weight']:
            if key in pattern and pattern[key]:
                setattr(existing, key, pattern[key])
        existing.last_synced_at = datetime.utcnow()
        db.session.commit()
        return False
    else:
        # Create new pattern
        new_pattern = AttackPattern(
            name=pattern['name'],
            description=pattern.get('description'),
            mitre_tactic=pattern.get('mitre_tactic'),
            mitre_technique=pattern.get('mitre_technique'),
            source=pattern.get('source', 'unknown'),
            source_id=pattern.get('source_id'),
            source_url=pattern.get('source_url'),
            pattern_type=pattern.get('pattern_type', 'single'),
            pattern_definition=pattern.get('pattern_definition', {}),
            clickhouse_query=pattern.get('clickhouse_query'),
            required_event_ids=pattern.get('required_event_ids'),
            required_channels=pattern.get('required_channels'),
            time_window_minutes=pattern.get('time_window_minutes', 60),
            severity=pattern.get('severity', 'medium'),
            confidence_weight=pattern.get('confidence_weight', 0.7),
            enabled=pattern.get('enabled', True),
            last_synced_at=datetime.utcnow(),
            created_by=pattern.get('created_by', 'sync_import')
        )
        db.session.add(new_pattern)
        db.session.commit()
        return True


# ============================================================================
# NON-AI PATTERN DETECTION
# ============================================================================

@celery_app.task(bind=True, name='tasks.detect_attack_patterns')
def detect_attack_patterns(
    self,
    case_id: int,
    case_uuid: str,
    categories: List[str] = None
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
        
    Returns:
        Dict with detection results
    """
    from utils.clickhouse import get_fresh_client
    from models.database import db
    from models.pattern_rules import ALL_PATTERN_RULES, PATTERN_CATEGORIES
    
    app = get_flask_app()
    
    with app.app_context():
        from models.rag import PatternRuleMatch
        
        client = get_fresh_client()
        
        self.update_state(state='PROGRESS', meta={
            'progress': 5,
            'status': 'Initializing pattern detection...'
        })
        
        # Clear existing matches for this case
        PatternRuleMatch.query.filter_by(case_id=case_id).delete()
        db.session.commit()
        
        # Filter patterns by category if specified
        if categories:
            patterns_to_check = [
                p for p in ALL_PATTERN_RULES 
                if p.get('category') in categories
            ]
        else:
            patterns_to_check = ALL_PATTERN_RULES
        
        total_patterns = len(patterns_to_check)
        matches_found = []
        errors = []
        
        # Noise filter to exclude events marked as noise
        noise_filter = " AND (noise_matched = false OR noise_matched IS NULL)"
        
        for idx, pattern in enumerate(patterns_to_check):
            try:
                progress = int(((idx + 1) / total_patterns) * 90) + 5
                self.update_state(state='PROGRESS', meta={
                    'progress': progress,
                    'status': f'Checking: {pattern["name"]}...',
                    'matches_found': len(matches_found)
                })
                
                if not pattern.get('detection_query'):
                    continue
                
                # Inject noise filter into query
                import re
                query_with_noise = pattern['detection_query']
                for keyword in ['GROUP BY', 'HAVING', 'ORDER BY', 'LIMIT']:
                    match = re.search(keyword, query_with_noise, re.IGNORECASE)
                    if match:
                        pos = match.start()
                        query_with_noise = query_with_noise[:pos] + noise_filter + ' ' + query_with_noise[pos:]
                        break
                else:
                    query_with_noise = query_with_noise.rstrip() + noise_filter
                
                # Run detection query
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
                        
                        # Create match record
                        match = PatternRuleMatch(
                            case_id=case_id,
                            pattern_id=pattern['id'],
                            pattern_name=pattern['name'],
                            category=pattern['category'],
                            description=pattern.get('description'),
                            severity=pattern.get('severity', 'medium'),
                            mitre_tactics=pattern.get('mitre_tactics'),
                            mitre_techniques=pattern.get('mitre_techniques'),
                            source_host=source_host,
                            username=username,
                            affected_users=affected_users[:20] if affected_users else None,
                            event_count=event_count,
                            first_seen=first_seen if isinstance(first_seen, datetime) else None,
                            last_seen=last_seen if isinstance(last_seen, datetime) else None,
                            duration_seconds=duration_seconds,
                            match_data={k: str(v)[:500] for k, v in row_dict.items()},
                            indicators=pattern.get('indicators', [])
                        )
                        db.session.add(match)
                        
                        matches_found.append({
                            'pattern_id': pattern['id'],
                            'pattern_name': pattern['name'],
                            'category': pattern['category'],
                            'severity': pattern['severity'],
                            'source_host': source_host,
                            'event_count': event_count
                        })
                        
            except Exception as e:
                logger.warning(f"[PatternRules] Pattern {pattern['name']} failed: {e}")
                errors.append(f"{pattern['name']}: {str(e)[:100]}")
        
        db.session.commit()
        
        # Calculate category summary
        category_counts = {}
        for match in matches_found:
            cat = match['category']
            category_counts[cat] = category_counts.get(cat, 0) + 1
        
        self.update_state(state='PROGRESS', meta={
            'progress': 100,
            'status': 'Complete',
            'matches_found': len(matches_found)
        })
        
        return {
            'success': True,
            'case_id': case_id,
            'case_uuid': case_uuid,
            'patterns_checked': len(patterns_to_check),
            'matches_found': len(matches_found),
            'categories_matched': category_counts,
            'matches': matches_found[:50],  # Limit response size
            'errors': errors[:10] if errors else None
        }
