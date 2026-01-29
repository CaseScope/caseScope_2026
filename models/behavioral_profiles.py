"""Behavioral Profile Models for CaseScope

Provides database models for behavioral profiling, peer groups, 
gap detection findings, suggested actions, and analysis run tracking.

These models support the Enhanced Analysis System which adds:
- Behavioral profiling for users and systems
- Peer group clustering for comparison
- Gap detection (attacks missed by per-event rules)
- Suggested analyst actions
"""

from datetime import datetime
from typing import List, Dict, Any, Optional
from models.database import db


class AnalysisMode:
    """Analysis operating modes based on feature availability"""
    A = 'A'  # Rule-based only (no AI, no OpenCTI)
    B = 'B'  # AI-enhanced (AI enabled, no OpenCTI)
    C = 'C'  # Intel-enriched (OpenCTI enabled, no AI)
    D = 'D'  # Full stack (both AI and OpenCTI)
    
    @classmethod
    def get_description(cls, mode: str) -> str:
        descriptions = {
            cls.A: 'Rule-based analysis with behavioral profiling',
            cls.B: 'AI-enhanced analysis with behavioral profiling',
            cls.C: 'Rule-based analysis with threat intelligence',
            cls.D: 'Full analysis with AI and threat intelligence'
        }
        return descriptions.get(mode, 'Unknown mode')


class AnalysisStatus:
    """Status values for case analysis runs"""
    PENDING = 'pending'
    PROFILING = 'profiling'
    CORRELATING = 'correlating'
    ANALYZING = 'analyzing'
    COMPLETE = 'complete'
    FAILED = 'failed'


class CaseAnalysisRun(db.Model):
    """Tracks overall analysis runs and their status
    
    Records each analysis run with timing, statistics, and 
    mode information for audit and progress tracking.
    """
    __tablename__ = 'case_analysis_runs'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=False, index=True)
    analysis_id = db.Column(db.String(36), nullable=False, unique=True, index=True)  # UUID
    
    # Status tracking
    status = db.Column(db.String(20), nullable=False, default=AnalysisStatus.PENDING, index=True)
    mode = db.Column(db.String(1), nullable=False)  # A, B, C, D
    ai_enabled = db.Column(db.Boolean, nullable=False, default=False)
    opencti_enabled = db.Column(db.Boolean, nullable=False, default=False)
    
    # Timing
    started_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    
    # Phase timestamps
    profiling_started_at = db.Column(db.DateTime, nullable=True)
    profiling_completed_at = db.Column(db.DateTime, nullable=True)
    correlation_started_at = db.Column(db.DateTime, nullable=True)
    correlation_completed_at = db.Column(db.DateTime, nullable=True)
    ai_analysis_started_at = db.Column(db.DateTime, nullable=True)
    ai_analysis_completed_at = db.Column(db.DateTime, nullable=True)
    
    # Statistics
    total_events_analyzed = db.Column(db.Integer, default=0)
    users_profiled = db.Column(db.Integer, default=0)
    systems_profiled = db.Column(db.Integer, default=0)
    peer_groups_created = db.Column(db.Integer, default=0)
    patterns_evaluated = db.Column(db.Integer, default=0)
    findings_generated = db.Column(db.Integer, default=0)
    high_confidence_findings = db.Column(db.Integer, default=0)
    
    # Error tracking
    error_message = db.Column(db.Text, nullable=True)
    
    # Progress for UI
    progress_percent = db.Column(db.Integer, default=0)
    current_phase = db.Column(db.String(100), nullable=True)
    
    # Relationships
    case = db.relationship('Case', backref=db.backref('analysis_runs', lazy='dynamic'))
    
    def __repr__(self):
        return f'<CaseAnalysisRun {self.analysis_id}: case={self.case_id} status={self.status}>'
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'case_id': self.case_id,
            'analysis_id': self.analysis_id,
            'status': self.status,
            'mode': self.mode,
            'mode_description': AnalysisMode.get_description(self.mode),
            'ai_enabled': self.ai_enabled,
            'opencti_enabled': self.opencti_enabled,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'total_events_analyzed': self.total_events_analyzed,
            'users_profiled': self.users_profiled,
            'systems_profiled': self.systems_profiled,
            'peer_groups_created': self.peer_groups_created,
            'patterns_evaluated': self.patterns_evaluated,
            'findings_generated': self.findings_generated,
            'high_confidence_findings': self.high_confidence_findings,
            'progress_percent': self.progress_percent,
            'current_phase': self.current_phase,
            'error_message': self.error_message
        }
    
    def update_progress(self, phase: str, percent: int, message: str = None):
        """Update progress for UI display"""
        self.current_phase = message or phase
        self.progress_percent = min(100, max(0, percent))
        db.session.commit()


class UserBehaviorProfile(db.Model):
    """Behavioral profile for a user in a case
    
    Stores computed behavioral baselines for anomaly detection
    and peer comparison.
    """
    __tablename__ = 'user_behavior_profiles'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('known_users.id'), nullable=False, index=True)
    username = db.Column(db.String(255), nullable=True)  # Denormalized for query convenience
    
    # Analysis period
    profile_period_start = db.Column(db.DateTime, nullable=True)
    profile_period_end = db.Column(db.DateTime, nullable=True)
    total_events = db.Column(db.Integer, default=0)
    
    # Activity patterns (JSONB)
    activity_hours = db.Column(db.JSON, nullable=True)  # Histogram of activity by hour (0-23)
    activity_days = db.Column(db.JSON, nullable=True)   # Histogram of activity by day of week
    peak_hours = db.Column(db.JSON, nullable=True)      # List of most active hours
    off_hours_percentage = db.Column(db.Float, default=0.0)  # Activity outside 7am-7pm
    
    # Authentication metrics
    total_logons = db.Column(db.Integer, default=0)
    logon_success_rate = db.Column(db.Float, default=0.0)
    auth_types = db.Column(db.JSON, nullable=True)  # Distribution: {kerberos: %, ntlm: %, other: %}
    
    # Host access patterns
    typical_source_hosts = db.Column(db.JSON, nullable=True)  # Hosts user logs in FROM
    typical_target_hosts = db.Column(db.JSON, nullable=True)  # Hosts user logs in TO
    unique_hosts_accessed = db.Column(db.Integer, default=0)
    
    # Daily statistics
    avg_daily_logons = db.Column(db.Float, default=0.0)
    std_daily_logons = db.Column(db.Float, default=0.0)
    max_daily_logons = db.Column(db.Integer, default=0)
    
    # Failure metrics
    failure_rate = db.Column(db.Float, default=0.0)
    avg_daily_failures = db.Column(db.Float, default=0.0)
    
    # Process execution (if Sysmon data available)
    processes_executed = db.Column(db.JSON, nullable=True)  # Common processes: [{process, count}]
    
    # Network activity (if available)
    network_connections = db.Column(db.JSON, nullable=True)  # Common destinations: [{dst_ip, count}]
    
    # Peer group reference
    peer_group_id = db.Column(db.Integer, db.ForeignKey('peer_groups.id'), nullable=True, index=True)
    
    # Anomaly detection thresholds
    anomaly_thresholds = db.Column(db.JSON, nullable=True)  # Computed thresholds
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    case = db.relationship('Case', backref=db.backref('user_behavior_profiles', lazy='dynamic'))
    user = db.relationship('KnownUser', backref=db.backref('behavior_profile', uselist=False))
    
    __table_args__ = (
        db.UniqueConstraint('case_id', 'user_id', name='uq_user_profile_case'),
    )
    
    def __repr__(self):
        return f'<UserBehaviorProfile {self.id}: {self.username}>'
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'case_id': self.case_id,
            'user_id': self.user_id,
            'username': self.username,
            'profile_period_start': self.profile_period_start.isoformat() if self.profile_period_start else None,
            'profile_period_end': self.profile_period_end.isoformat() if self.profile_period_end else None,
            'total_events': self.total_events,
            'activity_hours': self.activity_hours,
            'off_hours_percentage': self.off_hours_percentage,
            'total_logons': self.total_logons,
            'logon_success_rate': self.logon_success_rate,
            'auth_types': self.auth_types,
            'typical_source_hosts': self.typical_source_hosts,
            'typical_target_hosts': self.typical_target_hosts,
            'unique_hosts_accessed': self.unique_hosts_accessed,
            'avg_daily_logons': self.avg_daily_logons,
            'std_daily_logons': self.std_daily_logons,
            'failure_rate': self.failure_rate,
            'peer_group_id': self.peer_group_id,
            'anomaly_thresholds': self.anomaly_thresholds,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class SystemBehaviorProfile(db.Model):
    """Behavioral profile for a system in a case
    
    Stores computed behavioral baselines for system anomaly detection
    and peer comparison.
    """
    __tablename__ = 'system_behavior_profiles'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=False, index=True)
    system_id = db.Column(db.Integer, db.ForeignKey('known_systems.id'), nullable=False, index=True)
    hostname = db.Column(db.String(255), nullable=True)  # Denormalized for query convenience
    
    # Analysis period
    profile_period_start = db.Column(db.DateTime, nullable=True)
    profile_period_end = db.Column(db.DateTime, nullable=True)
    total_events = db.Column(db.Integer, default=0)
    
    # System role (inferred)
    system_role = db.Column(db.String(50), nullable=True)  # workstation, server, domain_controller
    
    # Activity patterns
    activity_hours = db.Column(db.JSON, nullable=True)  # Histogram of activity by hour
    
    # User access patterns
    typical_users = db.Column(db.JSON, nullable=True)  # Users who authenticate TO this system
    unique_users = db.Column(db.Integer, default=0)
    
    # Network patterns
    typical_source_ips = db.Column(db.JSON, nullable=True)  # IPs that normally connect
    
    # Process patterns
    typical_processes = db.Column(db.JSON, nullable=True)  # Normal processes on this system
    
    # Authentication volume (as destination)
    auth_destination_volume = db.Column(db.JSON, nullable=True)  # {mean_daily, std_daily, max_daily}
    
    # Authentication volume (as source)
    auth_source_volume = db.Column(db.JSON, nullable=True)  # {mean_daily, std_daily, max_daily}
    
    # Service accounts
    service_accounts = db.Column(db.JSON, nullable=True)  # Service accounts associated with this system
    
    # Network exposure
    network_listeners = db.Column(db.JSON, nullable=True)  # Ports/services normally exposed
    outbound_connections = db.Column(db.JSON, nullable=True)  # Normal outbound destinations
    
    # Peer group reference
    peer_group_id = db.Column(db.Integer, db.ForeignKey('peer_groups.id'), nullable=True, index=True)
    
    # Anomaly detection thresholds
    anomaly_thresholds = db.Column(db.JSON, nullable=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    case = db.relationship('Case', backref=db.backref('system_behavior_profiles', lazy='dynamic'))
    system = db.relationship('KnownSystem', backref=db.backref('behavior_profile', uselist=False))
    
    __table_args__ = (
        db.UniqueConstraint('case_id', 'system_id', name='uq_system_profile_case'),
    )
    
    def __repr__(self):
        return f'<SystemBehaviorProfile {self.id}: {self.hostname}>'
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'case_id': self.case_id,
            'system_id': self.system_id,
            'hostname': self.hostname,
            'profile_period_start': self.profile_period_start.isoformat() if self.profile_period_start else None,
            'profile_period_end': self.profile_period_end.isoformat() if self.profile_period_end else None,
            'total_events': self.total_events,
            'system_role': self.system_role,
            'activity_hours': self.activity_hours,
            'typical_users': self.typical_users,
            'unique_users': self.unique_users,
            'auth_destination_volume': self.auth_destination_volume,
            'peer_group_id': self.peer_group_id,
            'anomaly_thresholds': self.anomaly_thresholds,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class PeerGroup(db.Model):
    """Peer groups for behavioral comparison
    
    Clusters of similar users or systems that can be compared
    against each other for anomaly detection.
    """
    __tablename__ = 'peer_groups'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=False, index=True)
    
    group_type = db.Column(db.String(20), nullable=False, index=True)  # 'user' or 'system'
    group_name = db.Column(db.String(100), nullable=False)  # e.g., "standard_users_cluster_1"
    
    # Statistics
    member_count = db.Column(db.Integer, default=0)
    
    # Peer group medians for comparison
    median_daily_logons = db.Column(db.Float, nullable=True)
    median_failure_rate = db.Column(db.Float, nullable=True)
    median_unique_hosts = db.Column(db.Float, nullable=True)
    median_off_hours_pct = db.Column(db.Float, nullable=True)
    
    # Standard deviations for z-score calculation
    std_daily_logons = db.Column(db.Float, nullable=True)
    std_failure_rate = db.Column(db.Float, nullable=True)
    
    # Full statistical profile
    profile_data = db.Column(db.JSON, nullable=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    case = db.relationship('Case', backref=db.backref('peer_groups', lazy='dynamic'))
    members = db.relationship('PeerGroupMember', backref='peer_group', lazy='dynamic', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<PeerGroup {self.id}: {self.group_name} ({self.member_count} members)>'
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'case_id': self.case_id,
            'group_type': self.group_type,
            'group_name': self.group_name,
            'member_count': self.member_count,
            'median_daily_logons': self.median_daily_logons,
            'median_failure_rate': self.median_failure_rate,
            'median_unique_hosts': self.median_unique_hosts,
            'median_off_hours_pct': self.median_off_hours_pct,
            'profile_data': self.profile_data,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class PeerGroupMember(db.Model):
    """Membership records linking entities to peer groups"""
    __tablename__ = 'peer_group_members'
    
    id = db.Column(db.Integer, primary_key=True)
    peer_group_id = db.Column(db.Integer, db.ForeignKey('peer_groups.id', ondelete='CASCADE'), nullable=False, index=True)
    
    entity_type = db.Column(db.String(20), nullable=False)  # 'user' or 'system'
    entity_id = db.Column(db.Integer, nullable=False)  # FK to known_users or known_systems
    
    similarity_score = db.Column(db.Float, nullable=True)  # How closely this entity matches the group
    z_scores = db.Column(db.JSON, nullable=True)  # Z-scores vs group for each metric
    
    __table_args__ = (
        db.Index('ix_peer_member_entity', 'entity_type', 'entity_id'),
    )
    
    def __repr__(self):
        return f'<PeerGroupMember {self.entity_type}:{self.entity_id} in group {self.peer_group_id}>'


class GapDetectionFinding(db.Model):
    """Findings from gap detection (attacks missed by per-event rules)
    
    Stores findings from aggregate-based detection like password spraying,
    brute force, and behavioral anomalies.
    """
    __tablename__ = 'gap_detection_findings'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=False, index=True)
    analysis_id = db.Column(db.String(36), nullable=False, index=True)  # FK to case_analysis_runs
    
    # Finding type
    finding_type = db.Column(db.String(50), nullable=False, index=True)  # password_spraying, brute_force, anomalous_user, anomalous_system
    severity = db.Column(db.String(20), nullable=False, default='medium')  # critical, high, medium, low
    confidence = db.Column(db.Float, nullable=False, default=50.0)  # 0-100
    
    # Entity identification
    entity_type = db.Column(db.String(20), nullable=False)  # source_ip, user, system
    entity_value = db.Column(db.String(255), nullable=False)  # The IP, username, or hostname
    entity_id = db.Column(db.Integer, nullable=True)  # FK to known_users or known_systems
    
    # Description
    summary = db.Column(db.Text, nullable=False)  # One-line description
    details = db.Column(db.JSON, nullable=True)  # Full finding details
    evidence = db.Column(db.JSON, nullable=True)  # Supporting data points
    
    # Behavioral context
    behavioral_context = db.Column(db.JSON, nullable=True)  # Baseline vs observed comparison
    peer_comparison = db.Column(db.JSON, nullable=True)  # How entity compares to peers
    
    # Affected entities
    affected_entities = db.Column(db.JSON, nullable=True)  # List of targets/sources
    
    # Time window
    time_window_start = db.Column(db.DateTime, nullable=True)
    time_window_end = db.Column(db.DateTime, nullable=True)
    event_count = db.Column(db.Integer, default=0)
    
    # AI/OpenCTI enrichment (nullable based on mode)
    ai_reasoning = db.Column(db.Text, nullable=True)  # Mode B/D only
    opencti_context = db.Column(db.JSON, nullable=True)  # Mode C/D only
    
    # IOCs discovered
    suggested_iocs = db.Column(db.JSON, nullable=True)
    
    # Analyst review
    analyst_reviewed = db.Column(db.Boolean, default=False)
    analyst_verdict = db.Column(db.String(50), nullable=True)  # confirmed, false_positive, needs_investigation
    analyst_notes = db.Column(db.Text, nullable=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    case = db.relationship('Case', backref=db.backref('gap_detection_findings', lazy='dynamic'))
    
    __table_args__ = (
        db.Index('ix_gap_finding_case_type', 'case_id', 'finding_type'),
    )
    
    def __repr__(self):
        return f'<GapDetectionFinding {self.id}: {self.finding_type} - {self.entity_value}>'
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'case_id': self.case_id,
            'analysis_id': self.analysis_id,
            'finding_type': self.finding_type,
            'severity': self.severity,
            'confidence': self.confidence,
            'entity_type': self.entity_type,
            'entity_value': self.entity_value,
            'entity_id': self.entity_id,
            'summary': self.summary,
            'details': self.details,
            'evidence': self.evidence,
            'behavioral_context': self.behavioral_context,
            'peer_comparison': self.peer_comparison,
            'affected_entities': self.affected_entities,
            'time_window_start': self.time_window_start.isoformat() if self.time_window_start else None,
            'time_window_end': self.time_window_end.isoformat() if self.time_window_end else None,
            'event_count': self.event_count,
            'ai_reasoning': self.ai_reasoning,
            'opencti_context': self.opencti_context,
            'suggested_iocs': self.suggested_iocs,
            'analyst_reviewed': self.analyst_reviewed,
            'analyst_verdict': self.analyst_verdict,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class SuggestedAction(db.Model):
    """Suggested analyst actions based on findings
    
    Auto-generated recommendations like marking user/system compromised,
    adding IOCs, or flagging for investigation.
    """
    __tablename__ = 'suggested_actions'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=False, index=True)
    analysis_id = db.Column(db.String(36), nullable=False, index=True)
    
    # Source of suggestion
    source_type = db.Column(db.String(20), nullable=False)  # pattern_finding, gap_finding
    source_id = db.Column(db.Integer, nullable=False)  # FK to ai_analysis_results or gap_detection_findings
    
    # Action details
    action_type = db.Column(db.String(50), nullable=False, index=True)  # mark_user_compromised, mark_system_compromised, add_ioc, investigate
    target_type = db.Column(db.String(20), nullable=False)  # user, system, ioc
    target_id = db.Column(db.Integer, nullable=True)  # FK to relevant table
    target_value = db.Column(db.String(255), nullable=False)  # Human-readable target
    
    # Reasoning
    reason = db.Column(db.Text, nullable=False)  # Why this action is suggested
    confidence = db.Column(db.Float, nullable=False, default=50.0)  # How confident
    
    # Status
    status = db.Column(db.String(20), nullable=False, default='pending', index=True)  # pending, accepted, rejected, deferred
    accepted_by = db.Column(db.String(80), nullable=True)
    accepted_at = db.Column(db.DateTime, nullable=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    case = db.relationship('Case', backref=db.backref('suggested_actions', lazy='dynamic'))
    
    __table_args__ = (
        db.Index('ix_suggested_action_case_status', 'case_id', 'status'),
    )
    
    def __repr__(self):
        return f'<SuggestedAction {self.id}: {self.action_type} - {self.target_value}>'
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'case_id': self.case_id,
            'analysis_id': self.analysis_id,
            'source_type': self.source_type,
            'source_id': self.source_id,
            'action_type': self.action_type,
            'action_type_display': self._get_action_type_display(),
            'target_type': self.target_type,
            'target_id': self.target_id,
            'target_value': self.target_value,
            'reason': self.reason,
            'confidence': self.confidence,
            'status': self.status,
            'accepted_by': self.accepted_by,
            'accepted_at': self.accepted_at.isoformat() if self.accepted_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    def _get_action_type_display(self) -> str:
        displays = {
            'mark_user_compromised': 'Mark User Compromised',
            'mark_system_compromised': 'Mark System Compromised',
            'add_ioc': 'Add IOC',
            'investigate': 'Flag for Investigation'
        }
        return displays.get(self.action_type, self.action_type)
    
    def accept(self, username: str):
        """Accept this suggested action"""
        self.status = 'accepted'
        self.accepted_by = username
        self.accepted_at = datetime.utcnow()
        db.session.commit()
    
    def reject(self, username: str):
        """Reject this suggested action"""
        self.status = 'rejected'
        self.accepted_by = username
        self.accepted_at = datetime.utcnow()
        db.session.commit()


# Gap detection finding types
class GapFindingType:
    PASSWORD_SPRAYING = 'password_spraying'
    BRUTE_FORCE = 'brute_force'
    DISTRIBUTED_BRUTE_FORCE = 'distributed_brute_force'
    ANOMALOUS_USER = 'anomalous_user'
    ANOMALOUS_SYSTEM = 'anomalous_system'
    VOLUME_SPIKE = 'volume_spike'
    OFF_HOURS_ACTIVITY = 'off_hours_activity'
    NEW_TARGET_ACCESS = 'new_target_access'
    AUTH_METHOD_CHANGE = 'auth_method_change'


# System roles for inference
class SystemRole:
    DOMAIN_CONTROLLER = 'domain_controller'
    SERVER = 'server'
    WORKSTATION = 'workstation'
    UNKNOWN = 'unknown'


class OpenCTICache(db.Model):
    """Cache table for OpenCTI API responses during analysis
    
    Caches threat intelligence queries to avoid repeated API calls.
    Cache is scoped to case_id and cleared at start of new analysis runs.
    """
    __tablename__ = 'opencti_cache'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=False, index=True)
    query_type = db.Column(db.String(50), nullable=False, index=True)
    query_params_hash = db.Column(db.String(64), nullable=False, index=True)
    response_json = db.Column(db.JSON, nullable=True)
    cached_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    __table_args__ = (
        db.Index('ix_opencti_cache_lookup', 'case_id', 'query_type', 'query_params_hash'),
    )
