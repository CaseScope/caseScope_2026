"""RAG Models for CaseScope - Attack Patterns and Pattern Matches

Provides database models for:
- Attack patterns (from OpenCTI, SIGMA, CAR, analyst-defined)
- Pattern pieces (individual events that form attack sequences)
- Pattern matches (detected patterns in case events)
"""

from datetime import datetime
from typing import List, Dict, Any, Optional
from models.database import db


class AttackPattern(db.Model):
    """Attack pattern definitions from various sources
    
    Stores patterns from OpenCTI, SIGMA rules, MITRE CAR, and analyst-defined patterns.
    Each pattern can be matched against case events.
    """
    __tablename__ = 'attack_patterns'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    
    # MITRE ATT&CK mapping
    mitre_tactic = db.Column(db.String(100), nullable=True, index=True)
    mitre_technique = db.Column(db.String(50), nullable=True, index=True)
    mitre_sub_technique = db.Column(db.String(50), nullable=True)
    
    # Source tracking
    source = db.Column(db.String(50), nullable=False, index=True)  # opencti, sigma, car, elastic, analyst
    source_id = db.Column(db.String(255), nullable=True)  # Original ID from source
    source_url = db.Column(db.Text, nullable=True)  # Link back to source
    
    # Pattern definition (flexible JSON)
    pattern_type = db.Column(db.String(50), nullable=False)  # sequence, co-occurrence, single, threshold
    pattern_definition = db.Column(db.JSON, nullable=False, default=dict)
    
    # ClickHouse query template (pre-built for performance)
    clickhouse_query = db.Column(db.Text, nullable=True)
    
    # Detection context
    required_event_ids = db.Column(db.ARRAY(db.String), nullable=True)
    required_channels = db.Column(db.ARRAY(db.String), nullable=True)
    required_artifact_types = db.Column(db.ARRAY(db.String), nullable=True)
    time_window_minutes = db.Column(db.Integer, default=60)
    
    # Scoring
    severity = db.Column(db.String(20), default='medium')  # low, medium, high, critical
    confidence_weight = db.Column(db.Float, default=1.0)
    false_positive_rate = db.Column(db.Float, default=0.0)
    
    # Status
    enabled = db.Column(db.Boolean, default=True, index=True)
    last_synced_at = db.Column(db.DateTime, nullable=True)
    
    # Audit
    created_by = db.Column(db.String(80), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    pieces = db.relationship('PatternPiece', backref='pattern', lazy='dynamic', cascade='all, delete-orphan')
    matches = db.relationship('PatternMatch', backref='pattern', lazy='dynamic')
    
    # Unique constraint on source + source_id
    __table_args__ = (
        db.UniqueConstraint('source', 'source_id', name='uq_pattern_source'),
    )
    
    def __repr__(self):
        return f'<AttackPattern {self.id}: {self.name}>'
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'mitre_tactic': self.mitre_tactic,
            'mitre_technique': self.mitre_technique,
            'mitre_sub_technique': self.mitre_sub_technique,
            'source': self.source,
            'source_id': self.source_id,
            'pattern_type': self.pattern_type,
            'severity': self.severity,
            'confidence_weight': self.confidence_weight,
            'enabled': self.enabled,
            'time_window_minutes': self.time_window_minutes,
            'required_event_ids': self.required_event_ids,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_synced_at': self.last_synced_at.isoformat() if self.last_synced_at else None,
            'piece_count': self.pieces.count() if self.pieces else 0
        }
    
    @staticmethod
    def get_enabled_patterns() -> List['AttackPattern']:
        """Get all enabled patterns"""
        return AttackPattern.query.filter_by(enabled=True).all()
    
    @staticmethod
    def get_by_mitre(technique: str) -> List['AttackPattern']:
        """Get patterns by MITRE technique ID"""
        return AttackPattern.query.filter_by(
            mitre_technique=technique,
            enabled=True
        ).all()
    
    @staticmethod
    def get_by_source(source: str) -> List['AttackPattern']:
        """Get patterns by source"""
        return AttackPattern.query.filter_by(
            source=source,
            enabled=True
        ).all()


class PatternPiece(db.Model):
    """Individual event components that form attack patterns
    
    For sequence patterns, pieces have an order.
    For co-occurrence patterns, order is None.
    """
    __tablename__ = 'pattern_pieces'
    
    id = db.Column(db.Integer, primary_key=True)
    pattern_id = db.Column(db.Integer, db.ForeignKey('attack_patterns.id', ondelete='CASCADE'), nullable=False, index=True)
    
    piece_order = db.Column(db.Integer, nullable=True)  # Order in sequence (NULL for co-occurrence)
    piece_name = db.Column(db.String(100), nullable=False)
    
    # Matching criteria
    event_id_match = db.Column(db.ARRAY(db.String), nullable=True)
    channel_match = db.Column(db.ARRAY(db.String), nullable=True)
    artifact_type_match = db.Column(db.ARRAY(db.String), nullable=True)
    field_conditions = db.Column(db.JSON, nullable=True)  # e.g., {"logon_type": [3, 10]}
    search_terms = db.Column(db.ARRAY(db.String), nullable=True)  # Match in search_blob
    
    # Timing (for sequences)
    min_delay_seconds = db.Column(db.Integer, default=0)
    max_delay_seconds = db.Column(db.Integer, nullable=True)
    
    # Flags
    is_optional = db.Column(db.Boolean, default=False)
    is_anchor = db.Column(db.Boolean, default=False)  # Primary trigger event
    
    description = db.Column(db.Text, nullable=True)
    
    def __repr__(self):
        return f'<PatternPiece {self.id}: {self.piece_name}>'
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'pattern_id': self.pattern_id,
            'piece_order': self.piece_order,
            'piece_name': self.piece_name,
            'event_id_match': self.event_id_match,
            'channel_match': self.channel_match,
            'is_optional': self.is_optional,
            'is_anchor': self.is_anchor,
            'description': self.description
        }


class PatternMatch(db.Model):
    """Records of patterns matched in case events
    
    Tracks when and where patterns were detected, with confidence scores
    and links to the matched events.
    """
    __tablename__ = 'pattern_matches'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=False, index=True)
    pattern_id = db.Column(db.Integer, db.ForeignKey('attack_patterns.id'), nullable=False, index=True)
    
    # Match details
    confidence_score = db.Column(db.Float, nullable=False)
    matched_event_count = db.Column(db.Integer, nullable=True)
    time_span_seconds = db.Column(db.Integer, nullable=True)
    first_event_time = db.Column(db.DateTime, nullable=True)
    last_event_time = db.Column(db.DateTime, nullable=True)
    
    # ClickHouse event references
    matched_events = db.Column(db.JSON, nullable=True)  # [{row_id, event_id, timestamp}, ...]
    
    # Source host context
    source_host = db.Column(db.String(255), nullable=True)
    affected_users = db.Column(db.ARRAY(db.String), nullable=True)
    
    # AI analysis (populated by LLM)
    ai_summary = db.Column(db.Text, nullable=True)
    ai_confidence = db.Column(db.String(20), nullable=True)
    ai_explanation = db.Column(db.Text, nullable=True)
    
    # Analyst review
    analyst_reviewed = db.Column(db.Boolean, default=False)
    analyst_verdict = db.Column(db.String(50), nullable=True)  # confirmed, false_positive, needs_review
    analyst_notes = db.Column(db.Text, nullable=True)
    reviewed_by = db.Column(db.String(80), nullable=True)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    
    # Timeline inclusion
    include_in_timeline = db.Column(db.Boolean, default=False)
    
    # Timestamps
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship to case
    case = db.relationship('Case', backref=db.backref('pattern_matches', lazy='dynamic'))
    
    def __repr__(self):
        return f'<PatternMatch {self.id}: case={self.case_id} pattern={self.pattern_id}>'
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'case_id': self.case_id,
            'pattern_id': self.pattern_id,
            'pattern_name': self.pattern.name if self.pattern else None,
            'mitre_technique': self.pattern.mitre_technique if self.pattern else None,
            'confidence_score': self.confidence_score,
            'matched_event_count': self.matched_event_count,
            'time_span_seconds': self.time_span_seconds,
            'first_event_time': self.first_event_time.isoformat() if self.first_event_time else None,
            'last_event_time': self.last_event_time.isoformat() if self.last_event_time else None,
            'source_host': self.source_host,
            'affected_users': self.affected_users,
            'ai_summary': self.ai_summary,
            'ai_confidence': self.ai_confidence,
            'analyst_reviewed': self.analyst_reviewed,
            'analyst_verdict': self.analyst_verdict,
            'include_in_timeline': self.include_in_timeline,
            'discovered_at': self.discovered_at.isoformat() if self.discovered_at else None
        }
    
    def set_analyst_review(self, username: str, verdict: str, notes: str = None):
        """Record analyst review of this match"""
        self.analyst_reviewed = True
        self.analyst_verdict = verdict
        self.analyst_notes = notes
        self.reviewed_by = username
        self.reviewed_at = datetime.utcnow()
        
        # Auto-include confirmed matches in timeline
        if verdict == 'confirmed':
            self.include_in_timeline = True


class AttackCampaign(db.Model):
    """Attack campaigns detected by correlating pattern matches
    
    A campaign represents a higher-level attack behavior composed of
    multiple pattern matches that together indicate a specific attack type.
    """
    __tablename__ = 'attack_campaigns'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=False, index=True)
    
    # Campaign type (from CAMPAIGN_TEMPLATES)
    campaign_type = db.Column(db.String(100), nullable=False, index=True)
    campaign_name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    
    # Scoring
    confidence_score = db.Column(db.Float, nullable=False, default=0.0)
    severity = db.Column(db.String(20), default='medium')  # low, medium, high, critical
    
    # Scope
    affected_hosts = db.Column(db.ARRAY(db.String), nullable=True)
    affected_users = db.Column(db.ARRAY(db.String), nullable=True)
    host_count = db.Column(db.Integer, default=1)
    user_count = db.Column(db.Integer, default=0)
    
    # Timeline
    first_activity = db.Column(db.DateTime, nullable=True)
    last_activity = db.Column(db.DateTime, nullable=True)
    duration_seconds = db.Column(db.Integer, nullable=True)
    
    # Underlying evidence
    pattern_match_ids = db.Column(db.ARRAY(db.Integer), nullable=True)
    indicator_count = db.Column(db.Integer, default=0)  # Number of pattern matches
    matched_indicators = db.Column(db.JSON, nullable=True)  # Summary of what matched
    
    # MITRE ATT&CK
    mitre_tactics = db.Column(db.ARRAY(db.String), nullable=True)
    mitre_techniques = db.Column(db.ARRAY(db.String), nullable=True)
    
    # AI Analysis
    ai_summary = db.Column(db.Text, nullable=True)
    
    # Analyst review
    analyst_reviewed = db.Column(db.Boolean, default=False)
    analyst_verdict = db.Column(db.String(50), nullable=True)  # confirmed, false_positive, needs_review
    analyst_notes = db.Column(db.Text, nullable=True)
    reviewed_by = db.Column(db.String(80), nullable=True)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    
    # Timestamps
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    case = db.relationship('Case', backref=db.backref('attack_campaigns', lazy='dynamic'))
    
    def __repr__(self):
        return f'<AttackCampaign {self.id}: {self.campaign_type} case={self.case_id}>'
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'case_id': self.case_id,
            'campaign_type': self.campaign_type,
            'campaign_name': self.campaign_name,
            'description': self.description,
            'confidence_score': self.confidence_score,
            'severity': self.severity,
            'affected_hosts': self.affected_hosts or [],
            'affected_users': self.affected_users or [],
            'host_count': self.host_count,
            'user_count': self.user_count,
            'first_activity': self.first_activity.isoformat() if self.first_activity else None,
            'last_activity': self.last_activity.isoformat() if self.last_activity else None,
            'duration_seconds': self.duration_seconds,
            'indicator_count': self.indicator_count,
            'matched_indicators': self.matched_indicators,
            'pattern_match_ids': self.pattern_match_ids or [],
            'mitre_tactics': self.mitre_tactics or [],
            'mitre_techniques': self.mitre_techniques or [],
            'ai_summary': self.ai_summary,
            'analyst_reviewed': self.analyst_reviewed,
            'analyst_verdict': self.analyst_verdict,
            'detected_at': self.detected_at.isoformat() if self.detected_at else None
        }
    
    def set_analyst_review(self, username: str, verdict: str, notes: str = None):
        """Record analyst review"""
        self.analyst_reviewed = True
        self.analyst_verdict = verdict
        self.analyst_notes = notes
        self.reviewed_by = username
        self.reviewed_at = datetime.utcnow()


class PatternRuleMatch(db.Model):
    """Non-AI pattern rule detection results
    
    Stores matches from rule-based pattern detection (not AI/ML).
    Uses predefined detection patterns from models/pattern_rules.py
    """
    __tablename__ = 'pattern_rule_matches'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=False, index=True)
    
    # Pattern reference (from pattern_rules.py)
    pattern_id = db.Column(db.String(100), nullable=False, index=True)
    pattern_name = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(100), nullable=False, index=True)
    description = db.Column(db.Text, nullable=True)
    
    # Severity and MITRE mapping
    severity = db.Column(db.String(20), default='medium')  # low, medium, high, critical
    mitre_tactics = db.Column(db.ARRAY(db.String), nullable=True)
    mitre_techniques = db.Column(db.ARRAY(db.String), nullable=True)
    
    # Match details
    source_host = db.Column(db.String(255), nullable=True, index=True)
    username = db.Column(db.String(255), nullable=True)
    affected_users = db.Column(db.ARRAY(db.String), nullable=True)
    event_count = db.Column(db.Integer, default=1)
    
    # Timing
    first_seen = db.Column(db.DateTime, nullable=True)
    last_seen = db.Column(db.DateTime, nullable=True)
    duration_seconds = db.Column(db.Integer, nullable=True)
    
    # Raw match data from query
    match_data = db.Column(db.JSON, nullable=True)
    
    # Indicators that matched
    indicators = db.Column(db.ARRAY(db.String), nullable=True)
    
    # Analyst review
    analyst_reviewed = db.Column(db.Boolean, default=False)
    analyst_verdict = db.Column(db.String(50), nullable=True)  # confirmed, false_positive, needs_review
    analyst_notes = db.Column(db.Text, nullable=True)
    reviewed_by = db.Column(db.String(80), nullable=True)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    
    # Timestamps
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    case = db.relationship('Case', backref=db.backref('pattern_rule_matches', lazy='dynamic'))
    
    def __repr__(self):
        return f'<PatternRuleMatch {self.id}: {self.pattern_name} case={self.case_id}>'
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'case_id': self.case_id,
            'pattern_id': self.pattern_id,
            'pattern_name': self.pattern_name,
            'category': self.category,
            'description': self.description,
            'severity': self.severity,
            'mitre_tactics': self.mitre_tactics or [],
            'mitre_techniques': self.mitre_techniques or [],
            'source_host': self.source_host,
            'username': self.username,
            'affected_users': self.affected_users or [],
            'event_count': self.event_count,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'duration_seconds': self.duration_seconds,
            'indicators': self.indicators or [],
            'match_data': self.match_data,
            'analyst_reviewed': self.analyst_reviewed,
            'analyst_verdict': self.analyst_verdict,
            'detected_at': self.detected_at.isoformat() if self.detected_at else None
        }


# Campaign detection templates
CAMPAIGN_TEMPLATES = [
    {
        'type': 'password_spray',
        'name': 'Password Spray Attack',
        'description': 'Multiple failed login attempts across many accounts from similar sources',
        'severity': 'high',
        'mitre_tactics': ['Credential Access'],
        'mitre_techniques': ['T1110.003'],
        'detection_query': """
            SELECT 
                count(DISTINCT username) as unique_users,
                count() as total_failures,
                min(timestamp) as first_fail,
                max(timestamp) as last_fail,
                groupUniqArray(source_host) as source_hosts,
                groupUniqArray(username) as usernames
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND event_id = '4625'
                AND channel = 'Security'
            HAVING unique_users >= 10 AND total_failures >= 20
        """,
        'thresholds': {'min_users': 10, 'min_failures': 20, 'max_minutes': 60}
    },
    {
        'type': 'brute_force',
        'name': 'Brute Force Attack',
        'description': 'Repeated failed login attempts against same account',
        'severity': 'high',
        'mitre_tactics': ['Credential Access'],
        'mitre_techniques': ['T1110.001'],
        'detection_query': """
            SELECT 
                username,
                source_host,
                count() as fail_count,
                min(timestamp) as first_fail,
                max(timestamp) as last_fail,
                dateDiff('second', min(timestamp), max(timestamp)) as duration_secs
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND event_id = '4625'
                AND channel = 'Security'
            GROUP BY username, source_host
            HAVING fail_count >= 10 AND duration_secs <= 600
        """,
        'thresholds': {'min_failures': 10, 'max_seconds': 600}
    },
    {
        'type': 'lateral_movement_chain',
        'name': 'Lateral Movement Chain',
        'description': 'RDP or remote service access across multiple hosts in sequence',
        'severity': 'critical',
        'mitre_tactics': ['Lateral Movement'],
        'mitre_techniques': ['T1021.001', 'T1021.002'],
        'detection_query': """
            WITH remote_logins AS (
                SELECT 
                    source_host,
                    username,
                    timestamp,
                    logon_type
                FROM events
                WHERE case_id = {case_id:UInt32}
                    AND event_id = '4624'
                    AND channel = 'Security'
                    AND logon_type IN (3, 10)
            )
            SELECT 
                username,
                count(DISTINCT source_host) as hosts_accessed,
                groupUniqArray(source_host) as host_list,
                min(timestamp) as first_access,
                max(timestamp) as last_access
            FROM remote_logins
            GROUP BY username
            HAVING hosts_accessed >= 3
            ORDER BY hosts_accessed DESC
        """,
        'thresholds': {'min_hosts': 3}
    },
    {
        'type': 'pass_the_hash',
        'name': 'Pass-the-Hash Attack',
        'description': 'NTLM authentication with suspicious logon patterns indicating credential reuse',
        'severity': 'critical',
        'mitre_tactics': ['Credential Access', 'Lateral Movement'],
        'mitre_techniques': ['T1550.002'],
        'detection_query': """
            SELECT 
                username,
                source_host,
                count() as logon_count,
                groupUniqArray(logon_type) as logon_types,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND event_id = '4624'
                AND channel = 'Security'
                AND logon_type = 9
                AND (search_blob LIKE '%NTLM%' OR search_blob LIKE '%NtLmSsp%')
            GROUP BY username, source_host
            HAVING logon_count >= 1
        """,
        'thresholds': {'min_logons': 1}
    },
    {
        'type': 'cobalt_strike',
        'name': 'Cobalt Strike Indicators',
        'description': 'Process behaviors consistent with Cobalt Strike beacon activity',
        'severity': 'critical',
        'mitre_tactics': ['Command and Control', 'Execution'],
        'mitre_techniques': ['T1059.001', 'T1055'],
        'pattern_match_required': [
            {'pattern_names': ['PowerShell Execution', 'powershell'], 'min_count': 1},
            {'pattern_names': ['Service Installation', 'service'], 'min_count': 1}
        ],
        'search_terms': ['beacon', 'cobaltstrike', 'named pipe', '\\\\.\\pipe\\', 'postex', 'mimikatz'],
        'detection_query': """
            SELECT 
                source_host,
                count() as suspicious_events,
                groupArray(event_id) as event_ids,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (
                    lower(search_blob) LIKE '%beacon%'
                    OR lower(search_blob) LIKE '%cobaltstrike%'
                    OR lower(search_blob) LIKE '%\\\\\\\\.\\\\pipe\\\\%'
                    OR lower(search_blob) LIKE '%mimikatz%'
                    OR lower(search_blob) LIKE '%invoke-mimikatz%'
                    OR (process_name = 'rundll32.exe' AND command_line LIKE '%,a /p:%')
                )
            GROUP BY source_host
            HAVING suspicious_events >= 2
        """,
        'thresholds': {'min_indicators': 2}
    },
    {
        'type': 'persistence_cluster',
        'name': 'Persistence Mechanism Cluster',
        'description': 'Multiple persistence techniques deployed on same host',
        'severity': 'high',
        'mitre_tactics': ['Persistence'],
        'mitre_techniques': ['T1543.003', 'T1053.005', 'T1547.001'],
        'pattern_match_required': [
            {'pattern_names': ['Service Installation', 'Scheduled Task'], 'min_count': 2}
        ],
        'detection_query': """
            SELECT 
                source_host,
                countIf(event_id = '7045') as services_installed,
                countIf(event_id = '4698') as tasks_created,
                countIf(event_id = '13' AND channel LIKE '%Sysmon%') as registry_mods,
                services_installed + tasks_created + registry_mods as total_persistence,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (
                    event_id = '7045'
                    OR event_id = '4698'
                    OR (event_id = '13' AND channel LIKE '%Sysmon%' AND search_blob LIKE '%Run%')
                )
            GROUP BY source_host
            HAVING total_persistence >= 2
        """,
        'thresholds': {'min_mechanisms': 2}
    },
    {
        'type': 'defense_evasion',
        'name': 'Defense Evasion Activity',
        'description': 'Log clearing, disabling security, or other anti-forensics',
        'severity': 'critical',
        'mitre_tactics': ['Defense Evasion'],
        'mitre_techniques': ['T1070.001', 'T1562.001'],
        'detection_query': """
            SELECT 
                source_host,
                countIf(event_id IN ('1102', '104')) as logs_cleared,
                countIf(lower(search_blob) LIKE '%disable%' AND lower(search_blob) LIKE '%defender%') as defender_disabled,
                countIf(lower(search_blob) LIKE '%stop-service%' OR lower(search_blob) LIKE '%sc stop%') as services_stopped,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (
                    event_id IN ('1102', '104')
                    OR (lower(search_blob) LIKE '%disable%' AND lower(search_blob) LIKE '%defender%')
                    OR lower(search_blob) LIKE '%set-mppreference%'
                    OR lower(search_blob) LIKE '%-disablerealtimemonitoring%'
                )
            GROUP BY source_host
            HAVING logs_cleared + defender_disabled + services_stopped >= 1
        """,
        'thresholds': {'min_events': 1}
    },
    {
        'type': 'credential_dumping',
        'name': 'Credential Dumping',
        'description': 'Access to LSASS or credential stores indicating credential theft',
        'severity': 'critical',
        'mitre_tactics': ['Credential Access'],
        'mitre_techniques': ['T1003.001', 'T1003.002'],
        'detection_query': """
            SELECT 
                source_host,
                count() as dump_events,
                groupArray(process_name) as processes,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (
                    lower(search_blob) LIKE '%lsass%'
                    OR lower(search_blob) LIKE '%mimikatz%'
                    OR lower(search_blob) LIKE '%sekurlsa%'
                    OR lower(search_blob) LIKE '%procdump%lsass%'
                    OR lower(command_line) LIKE '%comsvcs.dll%minidump%'
                    OR (event_id = '10' AND lower(search_blob) LIKE '%lsass%')
                )
            GROUP BY source_host
            HAVING dump_events >= 1
        """,
        'thresholds': {'min_events': 1}
    },
    {
        'type': 'ransomware_precursor',
        'name': 'Ransomware Precursor Activity',
        'description': 'Shadow copy deletion, backup disruption, or encryption staging',
        'severity': 'critical',
        'mitre_tactics': ['Impact'],
        'mitre_techniques': ['T1490', 'T1486'],
        'detection_query': """
            SELECT 
                source_host,
                countIf(lower(search_blob) LIKE '%vssadmin%delete%') as vss_deletes,
                countIf(lower(search_blob) LIKE '%bcdedit%') as bcdedit_mods,
                countIf(lower(search_blob) LIKE '%wmic%shadowcopy%') as wmic_shadow,
                countIf(lower(search_blob) LIKE '%recoveryenabled%no%') as recovery_disabled,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (
                    lower(search_blob) LIKE '%vssadmin%delete%shadow%'
                    OR lower(search_blob) LIKE '%wmic%shadowcopy%delete%'
                    OR lower(search_blob) LIKE '%bcdedit%recoveryenabled%no%'
                    OR lower(search_blob) LIKE '%wbadmin%delete%catalog%'
                )
            GROUP BY source_host
            HAVING vss_deletes + bcdedit_mods + wmic_shadow + recovery_disabled >= 1
        """,
        'thresholds': {'min_events': 1}
    },
    {
        'type': 'data_exfiltration',
        'name': 'Data Exfiltration Indicators',
        'description': 'Large file transfers, archive creation, or cloud upload activity',
        'severity': 'high',
        'mitre_tactics': ['Exfiltration'],
        'mitre_techniques': ['T1041', 'T1567'],
        'detection_query': """
            SELECT 
                source_host,
                count() as exfil_indicators,
                groupArray(process_name) as processes,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen
            FROM events
            WHERE case_id = {case_id:UInt32}
                AND (
                    (process_name IN ('7z.exe', 'rar.exe', 'zip.exe') AND command_line LIKE '%a %')
                    OR lower(search_blob) LIKE '%rclone%'
                    OR lower(search_blob) LIKE '%mega%'
                    OR lower(search_blob) LIKE '%curl%upload%'
                    OR lower(search_blob) LIKE '%-outfile%'
                )
            GROUP BY source_host
            HAVING exfil_indicators >= 2
        """,
        'thresholds': {'min_events': 2}
    }
]


class RAGSyncLog(db.Model):
    """Tracks RAG pattern sync operations"""
    __tablename__ = 'rag_sync_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    source = db.Column(db.String(50), nullable=False)  # opencti, sigma, car
    sync_type = db.Column(db.String(50), nullable=False)  # full, incremental
    
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    
    patterns_added = db.Column(db.Integer, default=0)
    patterns_updated = db.Column(db.Integer, default=0)
    patterns_removed = db.Column(db.Integer, default=0)
    
    success = db.Column(db.Boolean, default=False)
    error_message = db.Column(db.Text, nullable=True)
    
    triggered_by = db.Column(db.String(80), nullable=True)
    
    def __repr__(self):
        return f'<RAGSyncLog {self.id}: {self.source} {self.sync_type}>'
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'source': self.source,
            'sync_type': self.sync_type,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'patterns_added': self.patterns_added,
            'patterns_updated': self.patterns_updated,
            'success': self.success,
            'error_message': self.error_message
        }


# Pre-defined attack patterns for initial seeding
BUILTIN_PATTERNS = [
    {
        'name': 'Brute Force to Successful Login',
        'description': 'Multiple failed logins followed by successful login from same source',
        'mitre_tactic': 'Credential Access',
        'mitre_technique': 'T1110',
        'source': 'builtin',
        'pattern_type': 'sequence',
        'severity': 'high',
        'confidence_weight': 0.9,
        'required_event_ids': ['4625', '4624'],
        'required_channels': ['Security'],
        'time_window_minutes': 60,
        'pattern_definition': {
            'type': 'sequence',
            'pieces': [
                {'name': 'failed_logins', 'event_id': '4625', 'min_count': 5, 'within_minutes': 10},
                {'name': 'successful_login', 'event_id': '4624', 'logon_type': [3, 10], 'after_minutes': 30}
            ]
        },
        'clickhouse_query': """
            WITH failed AS (
                SELECT source_host, username, count() as fail_count,
                       min(timestamp) as first_fail, max(timestamp) as last_fail
                FROM events
                WHERE case_id = {case_id:UInt32} AND event_id = '4625' AND channel = 'Security'
                GROUP BY source_host, username
                HAVING count() >= 5 AND dateDiff('minute', min(timestamp), max(timestamp)) <= 10
            )
            SELECT f.source_host, f.username, f.fail_count,
                   s.timestamp as success_time, f.first_fail, f.last_fail,
                   dateDiff('second', f.last_fail, s.timestamp) as delay_seconds
            FROM failed f
            JOIN events s ON s.case_id = {case_id:UInt32}
                AND s.event_id = '4624'
                AND s.channel = 'Security'
                AND s.username = f.username
                AND s.timestamp > f.last_fail
                AND s.timestamp < f.last_fail + INTERVAL 30 MINUTE
            ORDER BY f.fail_count DESC
        """
    },
    {
        'name': 'RDP Lateral Movement',
        'description': 'RDP login followed by process execution and potential outbound RDP',
        'mitre_tactic': 'Lateral Movement',
        'mitre_technique': 'T1021.001',
        'source': 'builtin',
        'pattern_type': 'sequence',
        'severity': 'high',
        'confidence_weight': 0.85,
        'required_event_ids': ['4624', '4688'],
        'time_window_minutes': 120,
        'pattern_definition': {
            'type': 'sequence',
            'pieces': [
                {'name': 'rdp_login', 'event_id': '4624', 'logon_type': [10]},
                {'name': 'process_exec', 'event_id': '4688', 'after_minutes': 30}
            ]
        },
        'clickhouse_query': """
            SELECT r.source_host, r.username, r.timestamp as rdp_time,
                   p.process_name, p.command_line, p.timestamp as exec_time,
                   dateDiff('second', r.timestamp, p.timestamp) as delay_seconds
            FROM events r
            JOIN events p ON p.case_id = r.case_id
                AND p.source_host = r.source_host
                AND p.event_id = '4688'
                AND p.timestamp > r.timestamp
                AND p.timestamp < r.timestamp + INTERVAL 30 MINUTE
            WHERE r.case_id = {case_id:UInt32}
                AND r.event_id = '4624'
                AND r.logon_type = 10
            ORDER BY r.timestamp
        """
    },
    {
        'name': 'Service Installation (Persistence)',
        'description': 'New service created - potential persistence mechanism',
        'mitre_tactic': 'Persistence',
        'mitre_technique': 'T1543.003',
        'source': 'builtin',
        'pattern_type': 'single',
        'severity': 'medium',
        'confidence_weight': 0.7,
        'required_event_ids': ['7045'],
        'required_channels': ['System'],
        'time_window_minutes': 0,
        'pattern_definition': {
            'type': 'single',
            'match': {'event_id': '7045', 'channel': 'System'}
        },
        'clickhouse_query': """
            SELECT source_host, timestamp, 
                   extractAllGroups(search_blob, 'Service Name: ([^\\n]+)')[1][1] as service_name,
                   extractAllGroups(search_blob, 'Service File Name: ([^\\n]+)')[1][1] as service_path,
                   search_blob
            FROM events
            WHERE case_id = {case_id:UInt32} AND event_id = '7045' AND channel = 'System'
            ORDER BY timestamp
        """
    },
    {
        'name': 'Scheduled Task Created',
        'description': 'New scheduled task registered - potential persistence or execution',
        'mitre_tactic': 'Persistence',
        'mitre_technique': 'T1053.005',
        'source': 'builtin',
        'pattern_type': 'single',
        'severity': 'medium',
        'confidence_weight': 0.7,
        'required_event_ids': ['4698'],
        'required_channels': ['Security'],
        'time_window_minutes': 0,
        'pattern_definition': {
            'type': 'single',
            'match': {'event_id': '4698', 'channel': 'Security'}
        },
        'clickhouse_query': """
            SELECT source_host, timestamp, username,
                   extractAllGroups(search_blob, 'Task Name: ([^\\n]+)')[1][1] as task_name,
                   search_blob
            FROM events
            WHERE case_id = {case_id:UInt32} AND event_id = '4698' AND channel = 'Security'
            ORDER BY timestamp
        """
    },
    {
        'name': 'Log Clearing',
        'description': 'Security or System log was cleared',
        'mitre_tactic': 'Defense Evasion',
        'mitre_technique': 'T1070.001',
        'source': 'builtin',
        'pattern_type': 'single',
        'severity': 'critical',
        'confidence_weight': 0.95,
        'required_event_ids': ['1102', '104'],
        'time_window_minutes': 0,
        'pattern_definition': {
            'type': 'single',
            'match': {'event_id': ['1102', '104']}
        },
        'clickhouse_query': """
            SELECT source_host, timestamp, event_id, channel, username, search_blob
            FROM events
            WHERE case_id = {case_id:UInt32} AND event_id IN ('1102', '104')
            ORDER BY timestamp
        """
    },
    {
        'name': 'PowerShell Execution',
        'description': 'PowerShell script block execution detected',
        'mitre_tactic': 'Execution',
        'mitre_technique': 'T1059.001',
        'source': 'builtin',
        'pattern_type': 'single',
        'severity': 'low',
        'confidence_weight': 0.5,
        'required_event_ids': ['4104'],
        'required_channels': ['Microsoft-Windows-PowerShell/Operational'],
        'time_window_minutes': 0,
        'pattern_definition': {
            'type': 'threshold',
            'match': {'event_id': '4104'},
            'threshold': 1
        },
        'clickhouse_query': """
            SELECT source_host, timestamp, username,
                   substring(search_blob, 1, 500) as script_preview
            FROM events
            WHERE case_id = {case_id:UInt32} 
                AND event_id = '4104' 
                AND channel = 'Microsoft-Windows-PowerShell/Operational'
            ORDER BY timestamp
            LIMIT 100
        """
    }
]


def seed_builtin_patterns():
    """Seed the database with built-in attack patterns"""
    from models.database import db
    
    added = 0
    for pattern_data in BUILTIN_PATTERNS:
        existing = AttackPattern.query.filter_by(
            source='builtin',
            name=pattern_data['name']
        ).first()
        
        if not existing:
            pattern = AttackPattern(
                name=pattern_data['name'],
                description=pattern_data['description'],
                mitre_tactic=pattern_data['mitre_tactic'],
                mitre_technique=pattern_data['mitre_technique'],
                source=pattern_data['source'],
                pattern_type=pattern_data['pattern_type'],
                pattern_definition=pattern_data['pattern_definition'],
                severity=pattern_data['severity'],
                confidence_weight=pattern_data['confidence_weight'],
                required_event_ids=pattern_data.get('required_event_ids'),
                required_channels=pattern_data.get('required_channels'),
                time_window_minutes=pattern_data.get('time_window_minutes', 60),
                clickhouse_query=pattern_data.get('clickhouse_query'),
                enabled=True,
                created_by='system'
            )
            db.session.add(pattern)
            added += 1
    
    db.session.commit()
    return added
