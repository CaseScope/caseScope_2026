"""Candidate Event Extraction for AI Correlation Analysis

Efficiently extracts events that could be part of attack patterns
from large event sets (30M+) for further AI analysis.

This module provides the first stage of the AI correlation pipeline:
1. Query ClickHouse for pattern-relevant events
2. Apply anchor/supporting/context roles
3. Tag with correlation keys for grouping
4. Store temporarily for AI analysis

Usage:
    extractor = CandidateExtractor(case_id=123, analysis_id='uuid')
    result = extractor.extract_pattern_candidates(
        pattern_config=PATTERN_EVENT_MAPPINGS['pass_the_hash'],
        time_start=datetime.now() - timedelta(days=1),
        time_end=datetime.now()
    )
"""

import logging
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple

from utils.clickhouse import get_fresh_client
from models.database import db

logger = logging.getLogger(__name__)


class CandidateExtractor:
    """Extracts candidate events for attack pattern analysis
    
    Optimized for large datasets (30M+ events) by:
    - Using indexed event_id filtering first
    - Applying time partitioning
    - Extracting only necessary columns
    - Batched database inserts
    """
    
    def __init__(self, case_id: int, analysis_id: str = None):
        """Initialize extractor
        
        Args:
            case_id: PostgreSQL case ID
            analysis_id: UUID for this analysis run (generated if not provided)
        """
        self.case_id = case_id
        self.analysis_id = analysis_id or str(uuid.uuid4())
        self.client = get_fresh_client()
        self._stats = {
            'queries_run': 0,
            'events_extracted': 0,
            'events_stored': 0
        }
        
    def extract_pattern_candidates(
        self,
        pattern_config: Dict,
        time_start: datetime = None,
        time_end: datetime = None,
        max_candidates: int = 50000
    ) -> Dict[str, Any]:
        """Extract candidate events for a specific attack pattern
        
        This is the main entry point for candidate extraction.
        
        Args:
            pattern_config: Pattern definition from PATTERN_EVENT_MAPPINGS
                Required keys: id, name, anchor_events, supporting_events
                Optional keys: context_events, anchor_conditions, correlation_fields
            time_start: Start of time range filter (inclusive)
            time_end: End of time range filter (inclusive)
            max_candidates: Maximum events to extract per role
            
        Returns:
            Dict with extraction results:
            {
                'analysis_id': str,
                'pattern_id': str,
                'anchor_count': int,
                'supporting_count': int,
                'context_count': int,
                'total_stored': int,
                'time_range': {'start': str, 'end': str},
                'stats': {...}
            }
        """
        pattern_id = pattern_config.get('id', 'unknown')
        pattern_name = pattern_config.get('name', 'Unknown Pattern')
        
        logger.info(f"[CandidateExtractor] Starting extraction for {pattern_name} (case {self.case_id})")
        
        # Build time filter clause
        time_filter = self._build_time_filter(time_start, time_end)
        if time_filter:
            logger.info(f"[CandidateExtractor] Time filter: {time_filter}")
        
        # OPTIMIZATION: Cheap probe — run a COUNT with full anchor conditions
        # before doing the expensive full extraction. If zero matches, skip entirely.
        anchor_conditions = pattern_config.get('anchor_conditions', {})
        if anchor_conditions:
            probe_count = self._probe_anchor_exists(
                event_ids=pattern_config.get('anchor_events', []),
                conditions=anchor_conditions,
                time_filter=time_filter
            )
            if probe_count == 0:
                logger.info(f"[CandidateExtractor] Anchor probe: 0 matches for {pattern_name}, skipping entirely")
                return {
                    'analysis_id': self.analysis_id,
                    'pattern_id': pattern_id,
                    'anchor_count': 0,
                    'supporting_count': 0,
                    'context_count': 0,
                    'total_stored': 0,
                    'skipped': True,
                    'skip_reason': 'anchor_probe_zero'
                }
            logger.info(f"[CandidateExtractor] Anchor probe: {probe_count} potential matches for {pattern_name}")
        
        # Extract anchor events (primary indicators - most specific)
        anchor_events = self._extract_events(
            event_ids=pattern_config.get('anchor_events', []),
            conditions=anchor_conditions,
            role='anchor',
            time_filter=time_filter,
            limit=max_candidates
        )
        
        # OPTIMIZATION #2: Skip supporting/context if no anchors found
        # Anchors are required for pattern matches - no point querying more without them
        if not anchor_events:
            logger.info(f"[CandidateExtractor] No anchor events found for {pattern_name}, skipping supporting/context queries")
            return {
                'analysis_id': self.analysis_id,
                'pattern_id': pattern_id,
                'pattern_name': pattern_name,
                'anchor_count': 0,
                'supporting_count': 0,
                'context_count': 0,
                'total_stored': 0,
                'skipped_no_anchors': True,
                'time_range': {
                    'start': time_start.isoformat() if time_start else None,
                    'end': time_end.isoformat() if time_end else None
                },
                'stats': self._stats.copy()
            }
        
        # Extract supporting events (corroborating evidence)
        supporting_events = self._extract_events(
            event_ids=pattern_config.get('supporting_events', []),
            conditions=pattern_config.get('supporting_conditions', {}),
            role='supporting',
            time_filter=time_filter,
            limit=max_candidates
        )
        
        # Extract context events (additional context, optional)
        context_events = []
        if pattern_config.get('context_events'):
            context_events = self._extract_events(
                event_ids=pattern_config['context_events'],
                conditions={},
                role='context',
                time_filter=time_filter,
                limit=max_candidates // 2
            )
        
        # Tag and store candidates
        correlation_fields = pattern_config.get('correlation_fields', ['source_host', 'username'])
        stored = self._store_candidates(
            pattern_id=pattern_id,
            pattern_name=pattern_name,
            anchor_events=anchor_events,
            supporting_events=supporting_events,
            context_events=context_events,
            correlation_fields=correlation_fields
        )
        
        self._stats['events_stored'] = stored
        
        return {
            'analysis_id': self.analysis_id,
            'pattern_id': pattern_id,
            'pattern_name': pattern_name,
            'anchor_count': len(anchor_events),
            'anchors': anchor_events,
            'supporting_count': len(supporting_events),
            'context_count': len(context_events),
            'total_stored': stored,
            'time_range': {
                'start': time_start.isoformat() if time_start else None,
                'end': time_end.isoformat() if time_end else None
            },
            'stats': self._stats.copy()
        }
    
    def _build_time_filter(
        self,
        time_start: datetime = None,
        time_end: datetime = None
    ) -> str:
        """Build SQL time filter clause
        
        Args:
            time_start: Start datetime
            time_end: End datetime
            
        Returns:
            SQL WHERE clause fragment (without AND prefix)
        """
        filters = []
        if time_start:
            filters.append(f"timestamp >= '{time_start.strftime('%Y-%m-%d %H:%M:%S')}'")
        if time_end:
            filters.append(f"timestamp <= '{time_end.strftime('%Y-%m-%d %H:%M:%S')}'")
        return " AND ".join(filters) if filters else ""
    
    def _extract_events(
        self,
        event_ids: List[str],
        conditions: Dict,
        role: str,
        time_filter: str = "",
        limit: int = 50000
    ) -> List[Dict]:
        """Extract events matching criteria from ClickHouse
        
        Optimized query strategy:
        1. Filter by case_id (partition key)
        2. Filter by event_id (indexed)
        3. Apply time filter (partition pruning)
        4. Apply specific conditions
        5. Select only needed columns
        
        Args:
            event_ids: List of Windows Event IDs to match
            conditions: Dict of field conditions per event_id
            role: Event role (anchor, supporting, context)
            time_filter: SQL time filter clause
            limit: Maximum events to return
            
        Returns:
            List of event dictionaries
        """
        if not event_ids:
            return []
        
        # Build event ID filter
        event_id_list = ", ".join(f"'{eid}'" for eid in event_ids)
        
        # Build condition filters for specific event types
        condition_clauses = self._build_condition_clauses(conditions)
        
        # Build final query
        where_parts = [
            f"case_id = {self.case_id}",
            f"event_id IN ({event_id_list})",
            "(noise_matched = false OR noise_matched IS NULL)"  # Exclude noise
        ]
        
        if time_filter:
            where_parts.append(time_filter)
        
        if condition_clauses:
            where_parts.append(f"({' OR '.join(condition_clauses)})")
        
        query = f"""
            SELECT 
                generateUUIDv4() as event_uuid,
                timestamp,
                event_id,
                source_host,
                username,
                channel,
                logon_type,
                process_name,
                command_line,
                JSONExtractString(raw_json, 'EventData', 'IpAddress') as src_ip,
                JSONExtractString(raw_json, 'EventData', 'TargetServerName') as target_host,
                JSONExtractString(raw_json, 'EventData', 'WorkstationName') as workstation,
                JSONExtractString(raw_json, 'EventData', 'KeyLength') as key_length,
                JSONExtractString(raw_json, 'EventData', 'LogonProcessName') as logon_process,
                JSONExtractString(raw_json, 'EventData', 'AuthenticationPackageName') as auth_package,
                JSONExtractString(raw_json, 'EventData', 'SubjectUserName') as subject_user,
                JSONExtractString(raw_json, 'EventData', 'TargetUserName') as target_user,
                substring(search_blob, 1, 500) as search_summary
            FROM events
            WHERE {' AND '.join(where_parts)}
            ORDER BY timestamp ASC
            LIMIT {limit}
        """
        
        self._stats['queries_run'] += 1
        
        try:
            result = self.client.query(query)
        except Exception as e:
            logger.error(f"[CandidateExtractor] Query failed for {role} events: {e}")
            return []
        
        events = []
        if result.result_rows:
            for row in result.result_rows:
                events.append({
                    'event_uuid': row[0],
                    'timestamp': row[1],
                    'event_id': row[2],
                    'source_host': row[3],
                    'username': row[4] or row[15] or row[16],  # Fallback to subject/target user
                    'channel': row[5],
                    'logon_type': row[6],
                    'process_name': row[7],
                    'command_line': row[8],
                    'src_ip': row[9],
                    'target_host': row[10] or row[11],  # Fallback to workstation
                    'key_length': row[12],
                    'logon_process': row[13],
                    'auth_package': row[14],
                    'search_summary': row[17],
                    'role': role
                })
        
        self._stats['events_extracted'] += len(events)
        logger.info(f"[CandidateExtractor] Extracted {len(events)} {role} events")
        return events
    
    def _probe_anchor_exists(
        self,
        event_ids: List[str],
        conditions: Dict,
        time_filter: str = ""
    ) -> int:
        """Cheap COUNT probe to check if any anchor events match the full conditions.
        
        Runs a single lightweight query with all anchor conditions applied.
        Returns 0 if nothing matches, allowing the caller to skip the pattern entirely
        without running the expensive full extraction + AI analysis.
        
        Args:
            event_ids: Anchor event IDs
            conditions: Anchor conditions dict (same format as anchor_conditions)
            time_filter: Optional time filter clause
            
        Returns:
            Count of matching events (0 = skip pattern)
        """
        if not event_ids:
            return 0
        
        event_id_list = ", ".join(f"'{eid}'" for eid in event_ids)
        condition_clauses = self._build_condition_clauses(conditions)
        
        where_parts = [
            f"case_id = {self.case_id}",
            f"event_id IN ({event_id_list})",
            "(noise_matched = false OR noise_matched IS NULL)"
        ]
        
        if time_filter:
            where_parts.append(time_filter)
        
        if condition_clauses:
            where_parts.append(f"({' OR '.join(condition_clauses)})")
        
        query = f"SELECT count() FROM events WHERE {' AND '.join(where_parts)}"
        
        try:
            result = self.client.query(query)
            count = result.result_rows[0][0] if result.result_rows else 0
            return count
        except Exception as e:
            # Fail-open: if probe fails, run the full extraction anyway
            logger.warning(f"[CandidateExtractor] Anchor probe query failed, proceeding with extraction: {e}")
            return 1  # Non-zero = don't skip
    
    def _build_condition_clauses(self, conditions: Dict) -> List[str]:
        """Build SQL condition clauses for specific event types
        
        Args:
            conditions: Dict mapping event_id to field conditions
                e.g., {'4624': {'logon_type': [3, 9], 'key_length': '0'}}
                
        Returns:
            List of SQL condition clauses
        """
        condition_clauses = []
        
        for event_id, conds in conditions.items():
            event_conds = [f"event_id = '{event_id}'"]
            
            for field, values in conds.items():
                if field == 'logon_type':
                    if isinstance(values, list):
                        event_conds.append(f"logon_type IN ({', '.join(str(v) for v in values)})")
                    else:
                        event_conds.append(f"logon_type = {values}")
                        
                elif field == 'key_length':
                    event_conds.append(
                        f"JSONExtractString(raw_json, 'EventData', 'KeyLength') = '{values}'"
                    )
                    
                elif field == 'auth_package':
                    if isinstance(values, list):
                        like_clauses = [f"search_blob LIKE '%{v}%'" for v in values]
                        event_conds.append(f"({' OR '.join(like_clauses)})")
                    else:
                        event_conds.append(f"search_blob LIKE '%{values}%'")
                        
                elif field == 'access_mask':
                    event_conds.append(
                        f"JSONExtractString(raw_json, 'EventData', 'AccessMask') = '{values}'"
                    )
                    
                elif field == 'properties':
                    # For DCSync detection - check for replication GUIDs
                    if isinstance(values, list):
                        like_clauses = [f"search_blob LIKE '%{v}%'" for v in values]
                        event_conds.append(f"({' OR '.join(like_clauses)})")
                        
                elif field == 'encryption_type':
                    if isinstance(values, list):
                        quoted_vals = ", ".join(f"'{v}'" for v in values)
                        event_conds.append(
                            f"JSONExtractString(raw_json, 'EventData', 'TicketEncryptionType') IN ({quoted_vals})"
                        )
                        
                else:
                    # Generic field handling
                    if isinstance(values, list):
                        val_list = ", ".join(f"'{v}'" for v in values)
                        event_conds.append(f"{field} IN ({val_list})")
                    else:
                        event_conds.append(f"{field} = '{values}'")
            
            condition_clauses.append(f"({' AND '.join(event_conds)})")
        
        return condition_clauses
    
    def _store_candidates(
        self,
        pattern_id: str,
        pattern_name: str,
        anchor_events: List[Dict],
        supporting_events: List[Dict],
        context_events: List[Dict],
        correlation_fields: List[str]
    ) -> int:
        """Store candidate events in database with tags
        
        Args:
            pattern_id: Pattern identifier
            pattern_name: Human-readable pattern name
            anchor_events: List of anchor event dicts
            supporting_events: List of supporting event dicts
            context_events: List of context event dicts
            correlation_fields: Fields to use for correlation key
            
        Returns:
            Number of events stored
        """
        from models.rag import CandidateEventSet
        
        all_events = anchor_events + supporting_events + context_events
        stored = 0
        batch = []
        batch_size = 1000
        
        for event in all_events:
            # Build correlation key for grouping related events
            correlation_key = self._build_correlation_key(event, correlation_fields)
            
            # Build condensed event summary for AI context
            event_summary = self._build_event_summary(event)
            
            candidate = CandidateEventSet(
                case_id=self.case_id,
                analysis_id=self.analysis_id,
                pattern_id=pattern_id,
                pattern_name=pattern_name,
                event_uuid=event['event_uuid'],
                event_timestamp=event['timestamp'],
                role=event['role'],
                correlation_key=correlation_key,
                event_id=event['event_id'],
                source_host=event.get('source_host'),
                username=event.get('username'),
                event_summary=event_summary
            )
            batch.append(candidate)
            stored += 1
            
            # Batch commit for performance
            if len(batch) >= batch_size:
                db.session.bulk_save_objects(batch)
                db.session.commit()
                batch = []
        
        # Final batch
        if batch:
            db.session.bulk_save_objects(batch)
            db.session.commit()
        
        logger.info(f"[CandidateExtractor] Stored {stored} candidates for {pattern_id}")
        return stored
    
    def _build_correlation_key(
        self,
        event: Dict,
        correlation_fields: List[str]
    ) -> str:
        """Build correlation key for grouping related events
        
        Args:
            event: Event dictionary
            correlation_fields: Fields to include in key
            
        Returns:
            Pipe-delimited correlation key
        """
        parts = []
        for field in correlation_fields:
            # Try direct field first, then alternatives
            val = event.get(field)
            if not val and field == 'source_host':
                val = event.get('workstation') or event.get('src_ip')
            if not val and field == 'target_host':
                val = event.get('target_host') or event.get('workstation')
            if not val and field == 'username':
                val = event.get('target_user') or event.get('subject_user')
            
            parts.append(str(val) if val else 'unknown')
        
        return '|'.join(parts)
    
    def _build_event_summary(self, event: Dict) -> str:
        """Build condensed event summary for AI context
        
        Creates a single-line summary with key fields for efficient
        LLM context usage.
        
        Args:
            event: Event dictionary
            
        Returns:
            Formatted event summary string
        """
        parts = [
            f"EventID:{event['event_id']}",
            f"Time:{event['timestamp']}",
        ]
        
        if event.get('source_host'):
            parts.append(f"Host:{event['source_host']}")
        if event.get('username'):
            parts.append(f"User:{event['username']}")
        if event.get('target_host'):
            parts.append(f"Target:{event['target_host']}")
        if event.get('src_ip'):
            parts.append(f"IP:{event['src_ip']}")
        if event.get('process_name'):
            parts.append(f"Process:{event['process_name']}")
        if event.get('logon_type'):
            parts.append(f"LogonType:{event['logon_type']}")
        if event.get('key_length'):
            parts.append(f"KeyLen:{event['key_length']}")
        if event.get('auth_package'):
            parts.append(f"Auth:{event['auth_package']}")
        if event.get('logon_process'):
            parts.append(f"LogonProc:{event['logon_process']}")
        
        return ' | '.join(parts)
    
    def get_correlation_keys(self, pattern_id: str) -> List[str]:
        """Get unique correlation keys for a pattern
        
        Args:
            pattern_id: Pattern identifier
            
        Returns:
            List of unique correlation keys
        """
        from models.rag import CandidateEventSet
        
        keys = db.session.query(
            CandidateEventSet.correlation_key
        ).filter_by(
            analysis_id=self.analysis_id,
            pattern_id=pattern_id
        ).distinct().all()
        
        return [k[0] for k in keys]
    
    def get_candidates_for_key(
        self,
        pattern_id: str,
        correlation_key: str,
        limit: int = 100
    ) -> List[Dict]:
        """Get candidate events for a specific correlation key
        
        Args:
            pattern_id: Pattern identifier
            correlation_key: Correlation key to filter
            limit: Maximum events to return
            
        Returns:
            List of candidate event dicts
        """
        from models.rag import CandidateEventSet
        
        candidates = CandidateEventSet.query.filter_by(
            analysis_id=self.analysis_id,
            pattern_id=pattern_id,
            correlation_key=correlation_key
        ).order_by(
            CandidateEventSet.event_timestamp.asc()
        ).limit(limit).all()
        
        return [{
            'event_uuid': c.event_uuid,
            'timestamp': c.event_timestamp,
            'event_id': c.event_id,
            'source_host': c.source_host,
            'username': c.username,
            'role': c.role,
            'summary': c.event_summary
        } for c in candidates]
    
    def cleanup(self):
        """Remove candidate events for this analysis
        
        Should be called after analysis completes to free up space.
        """
        from models.rag import CandidateEventSet
        
        deleted = CandidateEventSet.query.filter_by(
            analysis_id=self.analysis_id
        ).delete()
        db.session.commit()
        
        logger.info(f"[CandidateExtractor] Cleaned up {deleted} candidate events for analysis {self.analysis_id}")
        return deleted
    
    def get_stats(self) -> Dict[str, int]:
        """Get extraction statistics
        
        Returns:
            Dict with query and event counts
        """
        return self._stats.copy()
    
    # =========================================================================
    # BEHAVIORAL CONTEXT METHODS (Enhanced Analysis System)
    # =========================================================================
    
    def attach_behavioral_context(self, candidates: List[Dict]) -> List[Dict]:
        """
        For each candidate event group, lookup user and system profiles.
        Attach z-scores and anomaly flags.
        
        Args:
            candidates: List of candidate event groups
            
        Returns:
            list: Candidates with behavioral_context field added
        """
        from models.behavioral_profiles import UserBehaviorProfile, SystemBehaviorProfile
        from models.known_user import KnownUser
        from models.known_system import KnownSystem
        from config import Config
        
        z_threshold = getattr(Config, 'ANALYSIS_ANOMALY_Z_THRESHOLD', 3.0)
        
        for candidate in candidates:
            behavioral_context = {
                'user': None,
                'system': None,
                'anomaly_flags': [],
                'confidence_modifier': 0
            }
            
            # Get user context
            username = candidate.get('username')
            if username and not username.endswith('$'):
                user_context = self._get_user_behavioral_context(username)
                if user_context:
                    behavioral_context['user'] = user_context
                    
                    # Check for anomalies
                    for metric, z_score in user_context.get('z_scores', {}).items():
                        if abs(z_score) >= z_threshold:
                            behavioral_context['anomaly_flags'].append(
                                f"User {username}: {metric} z={z_score:.1f}"
                            )
            
            # Get system context
            source_host = candidate.get('source_host')
            if source_host:
                system_context = self._get_system_behavioral_context(source_host)
                if system_context:
                    behavioral_context['system'] = system_context
                    
                    # Check for anomalies
                    for metric, z_score in system_context.get('z_scores', {}).items():
                        if abs(z_score) >= z_threshold:
                            behavioral_context['anomaly_flags'].append(
                                f"System {source_host}: {metric} z={z_score:.1f}"
                            )
            
            # Calculate confidence modifier
            behavioral_context['confidence_modifier'] = self._calculate_behavioral_confidence_modifier(
                behavioral_context
            )
            
            candidate['behavioral_context'] = behavioral_context
        
        return candidates
    
    def _get_user_behavioral_context(self, username: str) -> Optional[Dict]:
        """Get behavioral profile for a user"""
        from models.behavioral_profiles import UserBehaviorProfile, PeerGroupMember
        from models.known_user import KnownUser
        
        known_user = KnownUser.query.filter_by(
            case_id=self.case_id
        ).filter(
            KnownUser.username.ilike(username)
        ).first()
        
        if not known_user:
            return None
        
        profile = UserBehaviorProfile.query.filter_by(
            case_id=self.case_id,
            user_id=known_user.id
        ).first()
        
        if not profile:
            return None
        
        context = {
            'has_profile': True,
            'avg_daily_logons': profile.avg_daily_logons,
            'failure_rate': profile.failure_rate,
            'off_hours_percentage': profile.off_hours_percentage,
            'z_scores': {}
        }
        
        # Get peer comparison if available
        if profile.peer_group_id:
            member = PeerGroupMember.query.filter_by(
                peer_group_id=profile.peer_group_id,
                entity_type='user',
                entity_id=known_user.id
            ).first()
            
            if member and member.z_scores:
                context['z_scores'] = member.z_scores
        
        return context
    
    def _get_system_behavioral_context(self, hostname: str) -> Optional[Dict]:
        """Get behavioral profile for a system"""
        from models.behavioral_profiles import SystemBehaviorProfile, PeerGroupMember
        from models.known_system import KnownSystem
        
        known_system = KnownSystem.query.filter_by(
            case_id=self.case_id
        ).filter(
            KnownSystem.hostname.ilike(hostname)
        ).first()
        
        if not known_system:
            return None
        
        profile = SystemBehaviorProfile.query.filter_by(
            case_id=self.case_id,
            system_id=known_system.id
        ).first()
        
        if not profile:
            return None
        
        context = {
            'has_profile': True,
            'system_role': profile.system_role,
            'unique_users': profile.unique_users,
            'z_scores': {}
        }
        
        if profile.peer_group_id:
            member = PeerGroupMember.query.filter_by(
                peer_group_id=profile.peer_group_id,
                entity_type='system',
                entity_id=known_system.id
            ).first()
            
            if member and member.z_scores:
                context['z_scores'] = member.z_scores
        
        return context
    
    def _calculate_behavioral_confidence_modifier(self, behavioral_context: Dict) -> float:
        """
        Calculate confidence modifier based on behavioral analysis.
        
        Returns:
            float: Modifier from -20 to +20
            
        Positive (more suspicious):
        - User z-score > 2 vs peers: +5 to +15
        - System z-score > 2 vs peers: +5 to +10
        - Off-hours activity: +5
        - New target access: +5
        
        Negative (less suspicious):
        - Behavior matches baseline: -10 to -20
        - Common pattern for this user/system: -5 to -10
        """
        modifier = 0.0
        
        user_context = behavioral_context.get('user')
        system_context = behavioral_context.get('system')
        anomaly_flags = behavioral_context.get('anomaly_flags', [])
        
        # User z-score anomalies: +5 to +15
        if user_context:
            z_scores = user_context.get('z_scores', {})
            max_z = max([abs(z) for z in z_scores.values()], default=0)
            
            if max_z >= 4:
                modifier += 15
            elif max_z >= 3:
                modifier += 10
            elif max_z >= 2:
                modifier += 5
            elif max_z < 1 and z_scores:
                # Behavior matches baseline closely
                modifier -= 10
            
            # Off-hours activity bonus
            off_hours = user_context.get('off_hours_percentage', 0)
            if off_hours and off_hours > 0.3:  # > 30% off-hours
                modifier += 5
        
        # System z-score anomalies: +5 to +10
        if system_context:
            z_scores = system_context.get('z_scores', {})
            max_z = max([abs(z) for z in z_scores.values()], default=0)
            
            if max_z >= 3:
                modifier += 10
            elif max_z >= 2:
                modifier += 5
            elif max_z < 1 and z_scores:
                modifier -= 5
        
        # Additional anomaly flags
        modifier += min(5, len(anomaly_flags))
        
        # Cap the modifier
        return max(-20, min(20, modifier))
    
    def attach_peer_comparison(self, candidates: List[Dict]) -> List[Dict]:
        """
        Add peer group comparison data to candidates.
        
        For each involved user/system:
        - Lookup peer group
        - Calculate z-scores vs peer median
        - Flag significant deviations
        
        Args:
            candidates: List of candidate event groups
            
        Returns:
            list: Candidates with peer_comparison field added
        """
        from models.behavioral_profiles import (
            UserBehaviorProfile, SystemBehaviorProfile,
            PeerGroup, PeerGroupMember
        )
        from models.known_user import KnownUser
        from models.known_system import KnownSystem
        
        for candidate in candidates:
            peer_comparison = {
                'user_peer_group': None,
                'system_peer_group': None,
                'significant_deviations': []
            }
            
            # Get user peer comparison
            username = candidate.get('username')
            if username and not username.endswith('$'):
                known_user = KnownUser.query.filter_by(
                    case_id=self.case_id
                ).filter(
                    KnownUser.username.ilike(username)
                ).first()
                
                if known_user:
                    profile = UserBehaviorProfile.query.filter_by(
                        case_id=self.case_id,
                        user_id=known_user.id
                    ).first()
                    
                    if profile and profile.peer_group_id:
                        peer_group = PeerGroup.query.get(profile.peer_group_id)
                        if peer_group:
                            peer_comparison['user_peer_group'] = {
                                'group_name': peer_group.group_name,
                                'member_count': peer_group.member_count,
                                'median_daily_logons': peer_group.median_daily_logons,
                                'median_failure_rate': peer_group.median_failure_rate
                            }
            
            # Get system peer comparison
            source_host = candidate.get('source_host')
            if source_host:
                known_system = KnownSystem.query.filter_by(
                    case_id=self.case_id
                ).filter(
                    KnownSystem.hostname.ilike(source_host)
                ).first()
                
                if known_system:
                    profile = SystemBehaviorProfile.query.filter_by(
                        case_id=self.case_id,
                        system_id=known_system.id
                    ).first()
                    
                    if profile and profile.peer_group_id:
                        peer_group = PeerGroup.query.get(profile.peer_group_id)
                        if peer_group:
                            peer_comparison['system_peer_group'] = {
                                'group_name': peer_group.group_name,
                                'member_count': peer_group.member_count
                            }
            
            candidate['peer_comparison'] = peer_comparison
        
        return candidates
