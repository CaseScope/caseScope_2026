"""Hayabusa Detection Correlator for CaseScope

Correlates Hayabusa/Sigma-tagged events into attack chains.

Hayabusa tags individual events with rule_title, mitre_tactics, etc.
This module groups related detections by:
- Time window
- Correlation key (user + host, source IP + target)
- MITRE tactic progression

Output: Correlated detection groups representing potential attack sequences.
"""

import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from collections import defaultdict

from models.database import db
from models.behavioral_profiles import (
    UserBehaviorProfile, SystemBehaviorProfile,
    PeerGroup, PeerGroupMember
)
from config import Config

logger = logging.getLogger(__name__)


# MITRE ATT&CK tactic order for kill chain progression
MITRE_TACTIC_ORDER = [
    'reconnaissance',
    'resource-development',
    'initial-access',
    'execution',
    'persistence',
    'privilege-escalation',
    'defense-evasion',
    'credential-access',
    'discovery',
    'lateral-movement',
    'collection',
    'command-and-control',
    'exfiltration',
    'impact'
]

# Severity ordering
SEVERITY_ORDER = ['informational', 'low', 'medium', 'high', 'critical']


class CorrelatedDetectionGroup:
    """
    Represents a group of correlated Hayabusa detections.
    """
    
    def __init__(self, correlation_key: str, case_id: int, analysis_id: str):
        self.correlation_key = correlation_key
        self.case_id = case_id
        self.analysis_id = analysis_id
        
        self.events: List[Dict] = []
        self.time_start: Optional[datetime] = None
        self.time_end: Optional[datetime] = None
        
        # Aggregated fields
        self.combined_severity: str = 'informational'
        self.mitre_tactics: List[str] = []
        self.mitre_techniques: List[str] = []
        self.rule_titles: List[str] = []
        
        # Attack chain analysis
        self.attack_chain_description: str = ''
        self.kill_chain_phases: List[str] = []
        self.chain_score: float = 0.0
        
        # Entities involved
        self.usernames: set = set()
        self.source_hosts: set = set()
        self.source_ips: set = set()
        self.remote_hosts: set = set()
        self.processes: set = set()
        
        # Behavioral context (added later)
        self.behavioral_context: Dict = {}
        self.anomaly_flags: List[str] = []
    
    def add_event(self, event: Dict):
        """Add an event to the group"""
        self.events.append(event)
        
        # Update time range
        ts = event.get('timestamp_utc')
        if ts:
            if self.time_start is None or ts < self.time_start:
                self.time_start = ts
            if self.time_end is None or ts > self.time_end:
                self.time_end = ts
        
        # Update severity (keep highest)
        event_severity = str(event.get('rule_level', 'informational')).lower()
        self._update_severity(event_severity)
        
        # Collect MITRE data
        tactics = event.get('mitre_tactics') or ''
        if tactics:
            for tactic in self._parse_mitre_field(tactics):
                if tactic and tactic not in self.mitre_tactics:
                    self.mitre_tactics.append(tactic)
        
        techniques = event.get('mitre_tags') or ''
        if techniques:
            for tech in self._parse_mitre_field(techniques):
                if tech and tech not in self.mitre_techniques:
                    self.mitre_techniques.append(tech)
        
        # Collect rule titles
        rule_title = event.get('rule_title', '')
        if rule_title and rule_title not in self.rule_titles:
            self.rule_titles.append(rule_title)
        
        # Collect entities
        if event.get('username'):
            self.usernames.add(event['username'])
        if event.get('source_host'):
            self.source_hosts.add(event['source_host'])
        if event.get('src_ip'):
            self.source_ips.add(str(event['src_ip']))
        if event.get('remote_host'):
            self.remote_hosts.add(event['remote_host'])
        if event.get('process_name'):
            self.processes.add(event['process_name'])
    
    def _parse_mitre_field(self, value: str) -> List[str]:
        """Parse MITRE field which may be comma-separated or array-like"""
        if not value:
            return []
        
        # Handle various formats
        value = str(value).strip()
        
        # Remove array brackets if present
        if value.startswith('[') and value.endswith(']'):
            value = value[1:-1]
        
        # Split and clean
        parts = value.replace("'", "").replace('"', '').split(',')
        return [p.strip().lower() for p in parts if p.strip()]
    
    def _update_severity(self, new_severity: str):
        """Update combined severity to the highest"""
        new_idx = SEVERITY_ORDER.index(new_severity) if new_severity in SEVERITY_ORDER else 0
        current_idx = SEVERITY_ORDER.index(self.combined_severity) if self.combined_severity in SEVERITY_ORDER else 0
        
        if new_idx > current_idx:
            self.combined_severity = new_severity
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        return {
            'correlation_key': self.correlation_key,
            'case_id': self.case_id,
            'analysis_id': self.analysis_id,
            'event_count': len(self.events),
            'time_start': self.time_start.isoformat() if self.time_start else None,
            'time_end': self.time_end.isoformat() if self.time_end else None,
            'duration_seconds': (self.time_end - self.time_start).total_seconds() 
                if self.time_start and self.time_end else 0,
            'combined_severity': self.combined_severity,
            'mitre_tactics': self.mitre_tactics,
            'mitre_techniques': self.mitre_techniques,
            'rule_titles': self.rule_titles,
            'attack_chain_description': self.attack_chain_description,
            'kill_chain_phases': self.kill_chain_phases,
            'chain_score': self.chain_score,
            'entities': {
                'usernames': list(self.usernames),
                'source_hosts': list(self.source_hosts),
                'source_ips': list(self.source_ips),
                'remote_hosts': list(self.remote_hosts),
                'processes': list(self.processes)
            },
            'behavioral_context': self.behavioral_context,
            'anomaly_flags': self.anomaly_flags,
            'events': self.events[:100]  # Limit event details in output
        }


class HayabusaCorrelator:
    """
    Correlates Hayabusa/Sigma detections into attack chains.
    
    Hayabusa tags individual events with rule_title, mitre_tactics, etc.
    This class groups related detections by:
    - Time window
    - Correlation key (user + host, or source IP + target)
    - MITRE tactic progression
    
    Output: Correlated detection groups that represent potential attack sequences.
    """
    
    # Attack chain patterns
    ATTACK_CHAIN_PATTERNS = {
        ('initial-access', 'execution'): 'Initial compromise with code execution',
        ('initial-access', 'persistence'): 'Initial access followed by persistence installation',
        ('credential-access', 'lateral-movement'): 'Credential theft with lateral movement',
        ('credential-access', 'privilege-escalation'): 'Credential theft for privilege escalation',
        ('persistence', 'defense-evasion'): 'Establishing persistence with defense evasion',
        ('execution', 'discovery'): 'Post-exploitation reconnaissance',
        ('discovery', 'collection'): 'Target identification and data collection',
        ('lateral-movement', 'credential-access'): 'Lateral movement with credential harvesting',
        ('privilege-escalation', 'credential-access'): 'Privilege escalation for credential access',
        ('command-and-control', 'exfiltration'): 'C2 communication with data exfiltration',
        ('collection', 'exfiltration'): 'Data collection followed by exfiltration',
        ('defense-evasion', 'execution'): 'Evasion techniques before execution',
    }
    
    def __init__(self, case_id: int, analysis_id: str, 
                 time_window_minutes: int = None,
                 progress_callback=None):
        """
        Args:
            case_id: The case to analyze
            analysis_id: UUID for this analysis run
            time_window_minutes: Time window for grouping related events
            progress_callback: Optional callable(phase, percent, message)
        """
        self.case_id = case_id
        self.analysis_id = analysis_id
        self.time_window_minutes = time_window_minutes or getattr(
            Config, 'ANALYSIS_TIME_WINDOW_MINUTES', 60
        )
        self.progress_callback = progress_callback
        self.ch_client = None
    
    def _update_progress(self, phase: str, percent: int, message: str):
        """Update progress if callback is set"""
        if self.progress_callback:
            self.progress_callback(phase, percent, message)
    
    def _get_clickhouse_client(self):
        """Get or create ClickHouse client"""
        if self.ch_client is None:
            from utils.clickhouse import get_fresh_client
            self.ch_client = get_fresh_client()
        return self.ch_client
    
    def correlate(self) -> List[CorrelatedDetectionGroup]:
        """
        Group related Hayabusa detections.
        
        Returns:
            list[CorrelatedDetectionGroup]: Grouped detections
        """
        self._update_progress('hayabusa_correlation', 35, 'Querying Hayabusa detections...')
        
        # Step 1: Get all Hayabusa-tagged events
        events = self._query_hayabusa_detections()
        
        if not events:
            logger.info("No Hayabusa detections found for correlation")
            return []
        
        logger.info(f"Found {len(events)} Hayabusa-tagged events to correlate")
        
        self._update_progress('hayabusa_correlation', 40, f'Clustering {len(events)} detections...')
        
        # Step 2: Cluster events by correlation key and time window
        clusters = self._find_detection_clusters(events)
        
        logger.info(f"Created {len(clusters)} detection clusters")
        
        self._update_progress('hayabusa_correlation', 45, 'Analyzing attack chains...')
        
        # Step 3: Analyze each cluster
        groups = []
        for key, cluster_events in clusters.items():
            group = self._analyze_cluster(key, cluster_events)
            if group and len(group.events) > 0:
                groups.append(group)
        
        self._update_progress('hayabusa_correlation', 48, 'Enriching with behavioral context...')
        
        # Step 4: Enrich with behavioral context
        for group in groups:
            self._enrich_with_behavioral_context(group)
        
        self._update_progress('hayabusa_correlation', 50, 
                             f'Correlation complete: {len(groups)} attack chains identified')
        
        # Sort by chain score (highest first)
        groups.sort(key=lambda g: g.chain_score, reverse=True)
        
        return groups
    
    def _query_hayabusa_detections(self) -> List[Dict]:
        """
        Query ClickHouse for events with rule_title set.
        
        Returns:
            list[dict]: Events with Hayabusa/Sigma detections
        """
        client = self._get_clickhouse_client()
        
        query = f"""
            SELECT 
                uuid,
                timestamp_utc,
                username,
                source_host,
                src_ip,
                remote_host,
                event_id,
                rule_title,
                rule_level,
                rule_file,
                mitre_tactics,
                mitre_tags,
                process_name,
                command_line,
                logon_type,
                auth_package
            FROM events
            WHERE case_id = {self.case_id}
              AND rule_title IS NOT NULL
              AND rule_title != ''
            ORDER BY timestamp_utc
        """
        
        try:
            result = client.query(query)
            
            events = []
            columns = [
                'record_id', 'timestamp_utc', 'username', 'source_host', 'src_ip',
                'remote_host', 'event_id', 'rule_title', 'rule_level', 'rule_file',
                'mitre_tactics', 'mitre_tags', 'process_name', 'command_line',
                'logon_type', 'auth_package'
            ]
            
            for row in result.result_rows:
                event = {}
                for i, col in enumerate(columns):
                    event[col] = row[i] if i < len(row) else None
                events.append(event)
            
            return events
            
        except Exception as e:
            logger.error(f"Failed to query Hayabusa detections: {e}")
            return []
    
    def _find_detection_clusters(self, events: List[Dict]) -> Dict[str, List[Dict]]:
        """
        Group events by time window and correlation key.
        
        Uses a sliding time window approach where events within
        time_window_minutes of each other are grouped together.
        """
        if not events:
            return {}
        
        # First, group by correlation key
        key_groups = defaultdict(list)
        for event in events:
            key = self._build_correlation_key(event)
            if key:
                key_groups[key].append(event)
        
        # Then, split each key group by time windows
        clusters = {}
        for key, group_events in key_groups.items():
            # Sort by timestamp
            sorted_events = sorted(
                group_events,
                key=lambda e: e.get('timestamp_utc') or datetime.min
            )
            
            # Split into time windows
            window_clusters = self._split_by_time_window(sorted_events)
            
            for i, cluster in enumerate(window_clusters):
                cluster_key = f"{key}|window_{i}"
                clusters[cluster_key] = cluster
        
        return clusters
    
    def _build_correlation_key(self, event: Dict) -> str:
        """
        Determine appropriate grouping key for an event.
        
        Options:
        - "{username}|{source_host}" for user-based correlation
        - "{src_ip}|{remote_host}" for network-based correlation
        - "{source_host}|{process_name}" for process-based correlation
        
        Selection based on event type and available fields.
        """
        username = event.get('username', '').strip() if event.get('username') else ''
        source_host = event.get('source_host', '').strip() if event.get('source_host') else ''
        src_ip = str(event.get('src_ip', '')).strip() if event.get('src_ip') else ''
        remote_host = event.get('remote_host', '').strip() if event.get('remote_host') else ''
        process_name = event.get('process_name', '').strip() if event.get('process_name') else ''
        
        # Filter out machine accounts for user correlation
        if username.endswith('$'):
            username = ''
        
        # Primary: User + Host (best for authentication/access events)
        if username and source_host:
            return f"user:{username}|host:{source_host}"
        
        # Secondary: Source IP + Remote Host (network-based correlation)
        if src_ip and src_ip not in ['', '0.0.0.0', '::'] and remote_host:
            return f"ip:{src_ip}|remote:{remote_host}"
        
        # Tertiary: Host + Process (process-based correlation)
        if source_host and process_name:
            return f"host:{source_host}|proc:{process_name}"
        
        # Fallback: Just host
        if source_host:
            return f"host:{source_host}"
        
        # Last resort: Just IP
        if src_ip and src_ip not in ['', '0.0.0.0', '::']:
            return f"ip:{src_ip}"
        
        return None
    
    def _split_by_time_window(self, sorted_events: List[Dict]) -> List[List[Dict]]:
        """
        Split a sorted list of events into time-based clusters.
        
        Events within time_window_minutes of each other are grouped.
        """
        if not sorted_events:
            return []
        
        window = timedelta(minutes=self.time_window_minutes)
        clusters = []
        current_cluster = []
        cluster_end = None
        
        for event in sorted_events:
            ts = event.get('timestamp_utc')
            if not ts:
                continue
            
            if not current_cluster:
                current_cluster.append(event)
                cluster_end = ts + window
            elif ts <= cluster_end:
                current_cluster.append(event)
                # Extend window from last event
                cluster_end = ts + window
            else:
                # Start new cluster
                if current_cluster:
                    clusters.append(current_cluster)
                current_cluster = [event]
                cluster_end = ts + window
        
        # Don't forget last cluster
        if current_cluster:
            clusters.append(current_cluster)
        
        return clusters
    
    def _analyze_cluster(self, key: str, events: List[Dict]) -> CorrelatedDetectionGroup:
        """
        Analyze a cluster of related detections.
        
        Determines:
        - Combined severity (highest among events)
        - Attack chain progression (tactic sequence)
        - Involved entities
        - Time span
        """
        # Strip the window suffix from key
        base_key = key.rsplit('|window_', 1)[0]
        
        group = CorrelatedDetectionGroup(base_key, self.case_id, self.analysis_id)
        
        for event in events:
            group.add_event(event)
        
        # Identify attack chain from tactics
        group.attack_chain_description = self._identify_attack_chain(
            group.mitre_tactics, 
            group.mitre_techniques
        )
        
        # Calculate chain score
        group.chain_score = self._calculate_chain_score(group)
        
        # Determine kill chain phases covered
        group.kill_chain_phases = self._map_to_kill_chain(group.mitre_tactics)
        
        return group
    
    def _identify_attack_chain(self, mitre_tactics: List[str], 
                               mitre_techniques: List[str]) -> str:
        """
        Map tactics to kill chain progression.
        
        Examples:
        - [initial-access, execution] → "Initial compromise with code execution"
        - [credential-access, lateral-movement] → "Credential theft with lateral movement"
        - [persistence, defense-evasion] → "Establishing persistence"
        
        Returns human-readable attack chain description.
        """
        if not mitre_tactics:
            return "Single detection (no tactic chain)"
        
        # Normalize tactics
        normalized = [t.strip().lower() for t in mitre_tactics if t]
        
        # Sort by kill chain order
        sorted_tactics = sorted(
            normalized,
            key=lambda t: MITRE_TACTIC_ORDER.index(t) if t in MITRE_TACTIC_ORDER else 99
        )
        
        if len(sorted_tactics) == 1:
            return f"Single tactic: {sorted_tactics[0].replace('-', ' ').title()}"
        
        # Check for known patterns
        for (t1, t2), description in self.ATTACK_CHAIN_PATTERNS.items():
            if t1 in sorted_tactics and t2 in sorted_tactics:
                return description
        
        # Build generic description from tactics
        if len(sorted_tactics) == 2:
            return f"{sorted_tactics[0].replace('-', ' ').title()} → {sorted_tactics[1].replace('-', ' ').title()}"
        
        # Multiple tactics - summarize
        first = sorted_tactics[0].replace('-', ' ').title()
        last = sorted_tactics[-1].replace('-', ' ').title()
        return f"Multi-stage attack: {first} through {last} ({len(sorted_tactics)} tactics)"
    
    def _calculate_chain_score(self, group: CorrelatedDetectionGroup) -> float:
        """
        Score the attack chain for prioritization.
        
        Factors:
        - Number of events
        - Severity
        - Number of distinct tactics (progression)
        - Kill chain coverage
        - High-value entity involvement
        """
        score = 0.0
        
        # Event count (more events = more significant)
        event_count = len(group.events)
        if event_count >= 10:
            score += 20
        elif event_count >= 5:
            score += 15
        elif event_count >= 3:
            score += 10
        else:
            score += 5
        
        # Severity
        severity_scores = {
            'critical': 30,
            'high': 20,
            'medium': 10,
            'low': 5,
            'informational': 2
        }
        score += severity_scores.get(group.combined_severity, 0)
        
        # Tactic count (more tactics = more complete attack chain)
        tactic_count = len(group.mitre_tactics)
        if tactic_count >= 5:
            score += 25
        elif tactic_count >= 3:
            score += 15
        elif tactic_count >= 2:
            score += 10
        
        # Kill chain progression bonus
        phases = self._map_to_kill_chain(group.mitre_tactics)
        if 'impact' in phases or 'exfiltration' in phases:
            score += 15  # Late stage = bad
        if 'initial-access' in phases and len(phases) > 1:
            score += 10  # Full chain from beginning
        
        # High-value entity involvement
        for username in group.usernames:
            if any(pat in username.lower() for pat in ['admin', 'domain', 'enterprise', 'svc_']):
                score += 10
                break
        
        return min(100, score)
    
    def _map_to_kill_chain(self, tactics: List[str]) -> List[str]:
        """Map MITRE tactics to kill chain phases, maintaining order"""
        if not tactics:
            return []
        
        phases = []
        for tactic in MITRE_TACTIC_ORDER:
            if tactic in [t.lower() for t in tactics]:
                phases.append(tactic)
        
        return phases
    
    def _enrich_with_behavioral_context(self, group: CorrelatedDetectionGroup):
        """
        Add behavioral baseline comparison to detection group.
        
        Adds:
        - User baseline vs observed behavior
        - System baseline vs observed behavior
        - Peer comparison z-scores
        - Anomaly flags
        """
        context = {
            'users': {},
            'systems': {}
        }
        
        # Enrich user context
        for username in list(group.usernames)[:5]:  # Limit to 5 users
            user_context = self._get_user_behavioral_context(username)
            if user_context:
                context['users'][username] = user_context
                
                # Check for anomalies
                if user_context.get('is_anomalous'):
                    group.anomaly_flags.append(f"User {username} behavior anomalous")
                if user_context.get('z_scores'):
                    for metric, z in user_context['z_scores'].items():
                        if abs(z) > 3:
                            group.anomaly_flags.append(
                                f"User {username}: {metric} z-score={z:.1f}"
                            )
        
        # Enrich system context
        for hostname in list(group.source_hosts)[:5]:
            system_context = self._get_system_behavioral_context(hostname)
            if system_context:
                context['systems'][hostname] = system_context
                
                if system_context.get('is_anomalous'):
                    group.anomaly_flags.append(f"System {hostname} behavior anomalous")
        
        group.behavioral_context = context
    
    def _get_user_behavioral_context(self, username: str) -> Optional[Dict]:
        """Get behavioral profile for a user"""
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
            'is_anomalous': False,
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
                # Check if any z-score exceeds threshold
                threshold = getattr(Config, 'ANALYSIS_ANOMALY_Z_THRESHOLD', 3.0)
                context['is_anomalous'] = any(
                    abs(z) >= threshold for z in member.z_scores.values()
                )
        
        return context
    
    def _get_system_behavioral_context(self, hostname: str) -> Optional[Dict]:
        """Get behavioral profile for a system"""
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
            'is_anomalous': False,
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
                threshold = getattr(Config, 'ANALYSIS_ANOMALY_Z_THRESHOLD', 3.0)
                context['is_anomalous'] = any(
                    abs(z) >= threshold for z in member.z_scores.values()
                )
        
        return context
