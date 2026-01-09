"""
CaseScope 2026 - Database Models
"""

from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from main import db


class User(UserMixin, db.Model):
    """User accounts for authentication"""
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(120))
    role = db.Column(db.String(20), default='analyst')  # administrator, analyst, read-only
    is_active = db.Column(db.Boolean, default=True)
    case_assigned = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=True)  # For read-only users
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Relationships
    assigned_case = db.relationship('Case', foreign_keys=[case_assigned], backref='viewers')
    
    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Verify password"""
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'


class Case(db.Model):
    """Investigation cases"""
    __tablename__ = 'case'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False, index=True)
    description = db.Column(db.Text)
    company = db.Column(db.String(200))
    status = db.Column(db.String(20), default='New')  # New, Assigned, In Progress, Completed, Archived
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # OpenSearch configuration
    opensearch_index = db.Column(db.String(100))  # OpenSearch index name (case-level, e.g., 'case_123')
    
    # Network infrastructure
    router_ips = db.Column(db.Text)  # Comma-separated router IPs
    vpn_ips = db.Column(db.Text)  # Comma-separated VPN IPs/subnets/ranges (e.g., 192.168.1.0/24, 10.0.0.50-10.0.0.60)
    
    # EDR reports
    edr_reports = db.Column(db.Text)  # EDR reports (separate multiple with *** NEW REPORT ***)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    creator = db.relationship('User', foreign_keys=[created_by], backref='cases_created')
    assignee = db.relationship('User', foreign_keys=[assigned_to], backref='cases_assigned')
    
    def __repr__(self):
        return f'<Case {self.name}>'


class CaseFile(db.Model):
    """
    Track uploaded files and their metadata
    ZIP-centric architecture: Containers (ZIPs) and Virtual files (extracted from ZIPs)
    """
    __tablename__ = 'case_file'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False, index=True)
    filename = db.Column(db.String(500), nullable=False)
    original_filename = db.Column(db.String(500))
    file_type = db.Column(db.String(50))  # evtx, json, csv, zip, pf, etc.
    file_size = db.Column(db.BigInteger)  # bytes
    file_path = db.Column(db.String(1000))  # storage path
    
    # File identification
    file_hash = db.Column(db.String(64), index=True)  # SHA256 hash for deduplication (ZIP-level)
    
    # File classification
    parser_type = db.Column(db.String(50), index=True)  # Parser used (evtx, edr, firewall, iis, etc.) - auto-determined, without '_parser' suffix
    
    # ZIP-centric fields (deprecated - will be removed in future version)
    is_container = db.Column(db.Boolean, default=False)  # True for ZIP files
    is_virtual = db.Column(db.Boolean, default=False, index=True)  # True for files extracted from ZIP
    target_index = db.Column(db.String(100))  # Target OpenSearch index (case_X, case_X_browser, etc.)
    
    # Processing status fields
    extraction_status = db.Column(db.String(50))  # For ZIP containers
    parsing_status = db.Column(db.String(50))  # For artifacts
    indexing_status = db.Column(db.String(50))  # For NDJSON
    
    # Parsed file paths
    parsed_file_path = db.Column(db.String(1000))  # Path to compressed NDJSON in staging
    parsed_at = db.Column(db.DateTime)
    
    # Compression details
    original_size = db.Column(db.BigInteger)  # Original size before processing
    compressed_size = db.Column(db.BigInteger)  # Size after GZIP compression
    compression_ratio = db.Column(db.Float)  # (1 - compressed/original) * 100
    
    # Artifact state tracking
    artifact_state = db.Column(db.String(50))  # raw, compressed, deleted
    ndjson_state = db.Column(db.String(50))  # pending, compressed, deleted
    artifact_compressed_path = db.Column(db.String(1000))  # Path to compressed artifact
    ndjson_compressed_path = db.Column(db.String(1000))  # Path to compressed NDJSON
    
    # Parsed metadata
    source_system = db.Column(db.String(200))  # Computer name from events
    source_user = db.Column(db.String(255))  # Username extracted from file path (e.g., C/Users/username/)
    event_count = db.Column(db.Integer, default=0)
    sigma_violations = db.Column(db.Integer, default=0)
    ioc_count = db.Column(db.Integer, default=0)
    
    # Hostname extraction tracking (new two-phase system)
    archive_type = db.Column(db.String(50))  # single_host, multi_host, unknown
    source_system_method = db.Column(db.String(50))  # evtx, lnk, filename, manual, path, ndjson
    source_system_confidence = db.Column(db.String(20))  # high, medium, low, pending
    suggested_source_system = db.Column(db.String(200))  # Alternative hostname found during processing
    user_specified_hostname = db.Column(db.String(200))  # Manually entered by user
    needs_review = db.Column(db.Boolean, default=False)  # Flag for hostname review
    
    # Upload tracking
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    # Processing status
    status = db.Column(db.String(50), default='pending')  # pending, processing, indexed, failed, extracting, parsing
    error_message = db.Column(db.Text)
    error_details = db.Column(db.Text)  # Detailed error messages for container processing
    files_failed = db.Column(db.Integer, default=0)  # Count of failed files in ZIP
    retry_count = db.Column(db.Integer, default=0)  # Number of retry attempts
    indexed_at = db.Column(db.DateTime)
    
    # Visibility flag - hide empty files by default
    is_hidden = db.Column(db.Boolean, default=False)  # True for files with 0 events
    
    # Relationships
    case = db.relationship('Case', backref='files')
    uploader = db.relationship('User', backref='uploaded_files')
    
    def __repr__(self):
        return f'<CaseFile {self.filename}>'


class IngestionProgress(db.Model):
    """
    Track file ingestion progress for resumable uploads
    Allows resuming interrupted ingestions exactly where they left off
    """
    __tablename__ = 'ingestion_progress'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id', ondelete='CASCADE'), nullable=False, index=True)
    started_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    started_by = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)
    status = db.Column(db.String(50), nullable=False, default='pending', index=True)  # pending, in_progress, completed, failed, aborted
    current_step = db.Column(db.String(50))  # staging, hashing, indexing, moving, cleanup
    total_files = db.Column(db.Integer, default=0)
    processed_files = db.Column(db.Integer, default=0)
    failed_files = db.Column(db.Integer, default=0)
    last_file_processed = db.Column(db.String(500))
    error_message = db.Column(db.Text)
    can_resume = db.Column(db.Boolean, default=True)
    completed_at = db.Column(db.DateTime)
    task_id = db.Column(db.String(255), index=True)  # Celery task ID for tracking
    
    # Relationships
    case = db.relationship('Case', backref='ingestion_progress')
    user = db.relationship('User', backref='started_ingestions')
    
    def __repr__(self):
        return f'<IngestionProgress case_id={self.case_id} status={self.status}>'


class AuditLog(db.Model):
    """
    Audit trail for security-sensitive actions
    Tracks user actions for compliance and security review
    """
    __tablename__ = 'audit_log'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True, nullable=True)
    username = db.Column(db.String(80))  # Denormalized for deleted users
    action = db.Column(db.String(100), index=True, nullable=False)
    resource_type = db.Column(db.String(50), index=True)  # user, case, file, ioc, etc.
    resource_id = db.Column(db.Integer)
    resource_name = db.Column(db.String(500))
    ip_address = db.Column(db.String(45))  # IPv4 or IPv6
    user_agent = db.Column(db.Text)
    details = db.Column(db.Text)  # JSON string with additional context
    status = db.Column(db.String(20), default='success')  # success, failed, error
    
    # Relationships
    user = db.relationship('User', backref='audit_logs')
    
    def __repr__(self):
        return f'<AuditLog {self.action} by {self.username}>'


class EventDescription(db.Model):
    """
    EVTX Event descriptions scraped from multiple sources
    Tracks Windows Event Log IDs with descriptions for better analysis
    """
    __tablename__ = 'event_description'
    
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.String(20), nullable=False, index=True)  # Event ID (e.g., "4624")
    log_source = db.Column(db.String(100), nullable=False, index=True)  # e.g., "Security", "System", "Application"
    description = db.Column(db.Text, nullable=False)  # Event description
    category = db.Column(db.String(100))  # Category (e.g., "Account Logon", "Object Access")
    subcategory = db.Column(db.String(100))  # Subcategory if available
    source_website = db.Column(db.String(200))  # Which website this was scraped from
    source_url = db.Column(db.String(500))  # Direct URL to the event description
    
    # Timestamps
    scraped_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Metadata
    description_length = db.Column(db.Integer)  # For selecting most descriptive version
    
    # Unique constraint: one entry per event_id + log_source combination
    __table_args__ = (
        db.UniqueConstraint('event_id', 'log_source', name='uix_event_log'),
        db.Index('idx_event_search', 'event_id', 'log_source'),
    )
    
    def __repr__(self):
        return f'<EventDescription {self.event_id} - {self.log_source}>'


class IOC(db.Model):
    """
    Indicators of Compromise - threat intelligence tracking
    """
    __tablename__ = 'iocs'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Core IOC Data
    type = db.Column(db.String(50), nullable=False, index=True)  # ipv4, domain, md5, etc.
    value = db.Column(db.Text, nullable=False, index=True)  # Truncated for index (max 2500 chars)
    full_value = db.Column(db.Text)  # Complete value for long command lines, base64, etc. (no index, unlimited)
    category = db.Column(db.String(50), nullable=False, index=True)  # network, file, host, etc.
    
    # Classification
    confidence = db.Column(db.SmallInteger)  # 0-100
    threat_level = db.Column(db.String(20), default='info', index=True)  # info, low, medium, high, critical
    is_whitelisted = db.Column(db.Boolean, default=False, index=True)
    is_active = db.Column(db.Boolean, default=True, index=True)
    is_hidden = db.Column(db.Boolean, default=False, index=True)  # Hide from default view
    
    # Temporal Data
    first_seen = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    times_seen = db.Column(db.Integer, default=1)
    expires_at = db.Column(db.DateTime)
    
    # Source & Attribution
    source = db.Column(db.String(50), default='manual', index=True)  # manual, ai_extraction, threat_feed, etc.
    source_reference = db.Column(db.Text)  # URL, feed name, case event ID, etc.
    description = db.Column(db.Text)
    analyst_notes = db.Column(db.Text)
    
    # Relationships
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=True, index=True)
    parent_ioc_id = db.Column(db.Integer, db.ForeignKey('iocs.id'), nullable=True)
    
    # Audit
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    updated_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    case = db.relationship('Case', backref='iocs')
    creator = db.relationship('User', foreign_keys=[created_by], backref='iocs_created')
    updater = db.relationship('User', foreign_keys=[updated_by], backref='iocs_updated')
    
    def __repr__(self):
        return f'<IOC {self.type}:{self.value}>'


class KnownSystem(db.Model):
    """
    Known Systems - Track systems/devices in investigation
    """
    __tablename__ = 'known_systems'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Core System Data
    hostname = db.Column(db.String(255), index=True)
    domain_name = db.Column(db.String(255), index=True)
    ip_address = db.Column(db.String(45), index=True)  # Supports IPv4 and IPv6
    
    # Classification
    compromised = db.Column(db.String(20), default='unknown', index=True)  # yes, no, unknown
    source = db.Column(db.String(50), default='manual', index=True)  # manual, logs
    system_type = db.Column(db.String(50), nullable=False, index=True)  # workstation, server, router, switch, printer, wap, other, threat_actor
    
    # Additional Details
    description = db.Column(db.Text)
    analyst_notes = db.Column(db.Text)
    
    # Relationships
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False, index=True)
    
    # Audit
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    updated_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    case = db.relationship('Case', backref='known_systems')
    creator = db.relationship('User', foreign_keys=[created_by], backref='systems_created')
    updater = db.relationship('User', foreign_keys=[updated_by], backref='systems_updated')
    
    def __repr__(self):
        return f'<KnownSystem {self.hostname or self.ip_address}>'


class KnownUser(db.Model):
    """
    Known Users - Track user accounts in investigation
    """
    __tablename__ = 'known_users'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Core User Data
    username = db.Column(db.String(255), nullable=False, index=True)
    domain_name = db.Column(db.String(255), index=True)  # Domain or hostname for local users
    sid = db.Column(db.String(255), index=True)  # Security Identifier
    
    # Classification
    compromised = db.Column(db.String(20), default='no', index=True)  # yes, no
    user_type = db.Column(db.String(50), default='unknown', index=True)  # domain, local, unknown
    source = db.Column(db.String(50), default='manual', index=True)  # manual, logs, ioc_extraction
    
    # Additional Details
    description = db.Column(db.Text)
    analyst_notes = db.Column(db.Text)
    
    # Relationships
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False, index=True)
    
    # Audit
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    updated_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    case = db.relationship('Case', backref='known_users')
    creator = db.relationship('User', foreign_keys=[created_by], backref='users_created')
    updater = db.relationship('User', foreign_keys=[updated_by], backref='users_updated')
    
    def __repr__(self):
        return f'<KnownUser {self.domain_name}\\{self.username}>' if self.domain_name else f'<KnownUser {self.username}>'


class EventIOCHit(db.Model):
    """
    Tracks which events contain which IOCs
    Links OpenSearch events to IOC database entries
    """
    __tablename__ = 'event_ioc_hits'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False, index=True)
    
    # Event identification
    opensearch_doc_id = db.Column(db.String(255), nullable=False, index=True)
    source_index = db.Column(db.String(100))  # e.g., 'case_3', 'case_3_browser'
    event_record_id = db.Column(db.BigInteger)
    event_id = db.Column(db.String(255), index=True)
    event_timestamp = db.Column(db.DateTime)
    computer = db.Column(db.String(255))
    
    # IOC information
    ioc_id = db.Column(db.Integer, db.ForeignKey('iocs.id'), nullable=False, index=True)
    ioc_value = db.Column(db.String(1000), nullable=False)
    ioc_type = db.Column(db.String(50), index=True)
    ioc_category = db.Column(db.String(50))
    threat_level = db.Column(db.String(20), index=True)
    
    # Match details
    matched_in_field = db.Column(db.String(255))
    match_context = db.Column(db.Text)
    confidence = db.Column(db.String(20), default='high')
    
    # Metadata
    detected_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    detected_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # Relationships
    case = db.relationship('Case', backref='ioc_hits')
    ioc = db.relationship('IOC', backref='event_hits')
    detector = db.relationship('User', backref='ioc_detections')
    
    def __repr__(self):
        return f'<EventIOCHit IOC:{self.ioc_id} in Event:{self.opensearch_doc_id}>'


class SigmaRule(db.Model):
    """
    Tracks SIGMA rules available in the system and their enabled/disabled status
    """
    __tablename__ = 'sigma_rules'
    
    id = db.Column(db.Integer, primary_key=True)
    rule_path = db.Column(db.String(512), nullable=False, unique=True, index=True)  # Relative path from rules/sigma/rules/
    rule_id = db.Column(db.String(255))  # UUID from rule file
    rule_title = db.Column(db.String(512))  # Title from rule file
    rule_level = db.Column(db.String(50), index=True)  # critical, high, medium, low
    rule_status = db.Column(db.String(50))  # Status from rule file (stable, experimental, etc.)
    rule_category = db.Column(db.String(255), index=True)  # e.g., 'windows/process_creation'
    logsource = db.Column(db.JSON)  # Logsource information from rule
    mitre_tags = db.Column(db.Text)  # Comma-separated MITRE ATT&CK tags
    is_enabled = db.Column(db.Boolean, default=True, nullable=False, index=True)  # Whether the rule is enabled
    source_folder = db.Column(db.String(255), default='rules', index=True)  # rules, rules-emerging-threats, etc.
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_synced = db.Column(db.DateTime)  # Last time rules were synced from disk
    
    def __repr__(self):
        return f'<SigmaRule {self.rule_title} ({self.rule_path})>'


class EventSigmaHit(db.Model):
    """
    Tracks which events match which Sigma rules
    Links OpenSearch events to Sigma rule detections
    """
    __tablename__ = 'event_sigma_hits'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False, index=True)
    
    # Event identification
    opensearch_doc_id = db.Column(db.String(255), nullable=False, index=True)
    event_record_id = db.Column(db.BigInteger)
    event_id = db.Column(db.String(255), index=True)
    event_timestamp = db.Column(db.DateTime)
    computer = db.Column(db.String(255))
    
    # File that was scanned
    file_id = db.Column(db.Integer, db.ForeignKey('case_file.id'))
    
    # Sigma rule information
    sigma_rule_id = db.Column(db.String(500), nullable=False, index=True)
    rule_title = db.Column(db.Text)
    rule_level = db.Column(db.String(50), index=True)  # critical, high, medium, low, informational
    mitre_tags = db.Column(db.Text)  # comma-separated MITRE ATT&CK tags
    
    # Match details
    matched_field = db.Column(db.String(255))
    confidence = db.Column(db.String(20), default='high')
    
    # Metadata
    detected_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    detected_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # Relationships
    case = db.relationship('Case', backref='sigma_hits')
    file = db.relationship('CaseFile', backref='sigma_hits')
    detector = db.relationship('User', backref='sigma_detections')
    
    def __repr__(self):
        return f'<EventSigmaHit Rule:{self.sigma_rule_id} in Event:{self.opensearch_doc_id}>'


class NoiseFilterCategory(db.Model):
    """
    Categories for organizing noise filter rules
    """
    __tablename__ = 'noise_filter_categories'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True, index=True)
    description = db.Column(db.Text)
    is_enabled = db.Column(db.Boolean, default=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    rules = db.relationship('NoiseFilterRule', backref='category', cascade='all, delete-orphan', lazy='dynamic')
    
    def __repr__(self):
        return f'<NoiseFilterCategory {self.name}>'


class NoiseFilterRule(db.Model):
    """
    Noise filter rules for hiding known good software/tools
    """
    __tablename__ = 'noise_filter_rules'
    
    id = db.Column(db.Integer, primary_key=True)
    category_id = db.Column(db.Integer, db.ForeignKey('noise_filter_categories.id', ondelete='CASCADE'), index=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    
    # Filter configuration
    filter_type = db.Column(db.String(50), nullable=False, index=True)  # process_name, file_path, command_line, hash, guid, network_connection
    pattern = db.Column(db.String(1000), nullable=False)  # The pattern to match
    match_mode = db.Column(db.String(20), default='contains')  # exact, contains, starts_with, ends_with, regex, wildcard
    is_case_sensitive = db.Column(db.Boolean, default=False)
    exclude_fields = db.Column(db.String(500))  # Comma-separated list of field names to exclude from matching (e.g., 'agent.url,url,subdomain')
    
    # Status and metadata
    is_enabled = db.Column(db.Boolean, default=True, index=True)
    is_system_default = db.Column(db.Boolean, default=False, index=True)  # True for built-in defaults
    priority = db.Column(db.Integer, default=100, index=True)  # Lower number = higher priority
    
    # Audit
    created_by = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'))
    updated_by = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    creator = db.relationship('User', foreign_keys=[created_by], backref='noise_rules_created')
    updater = db.relationship('User', foreign_keys=[updated_by], backref='noise_rules_updated')
    
    def __repr__(self):
        return f'<NoiseFilterRule {self.name}>'


class NoiseFilterStats(db.Model):
    """
    Track how many events were filtered by each rule
    """
    __tablename__ = 'noise_filter_stats'
    
    id = db.Column(db.Integer, primary_key=True)
    rule_id = db.Column(db.Integer, db.ForeignKey('noise_filter_rules.id', ondelete='CASCADE'), index=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id', ondelete='CASCADE'), index=True)
    events_filtered = db.Column(db.Integer, default=0)
    last_matched = db.Column(db.DateTime, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    rule = db.relationship('NoiseFilterRule', backref='stats')
    case = db.relationship('Case', backref='noise_filter_stats')
    
    def __repr__(self):
        return f'<NoiseFilterStats Rule:{self.rule_id} Case:{self.case_id}>'


class ActiveTask(db.Model):
    """
    Track active Celery tasks for reconnection and progress monitoring
    Allows users to reconnect to running tasks after page refresh or navigation
    """
    __tablename__ = 'active_tasks'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id', ondelete='CASCADE'), nullable=False, index=True)
    task_type = db.Column(db.String(50), nullable=False, index=True)  # 'ioc_hunt', 'sigma_hunt', 'noise_tagging'
    task_id = db.Column(db.String(255), nullable=False, unique=True, index=True)  # Celery task UUID
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False, index=True)
    
    # Task status and progress
    status = db.Column(db.String(20), default='running', index=True)  # running, completed, failed, cancelled
    progress_percent = db.Column(db.Integer, default=0)
    progress_message = db.Column(db.String(500))
    
    # Timing
    started_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    completed_at = db.Column(db.DateTime)
    task_id = db.Column(db.String(255), index=True)  # Celery task ID for tracking
    
    # Results (stored as JSON)
    result_data = db.Column(db.JSON)
    error_message = db.Column(db.Text)
    
    # Relationships
    case = db.relationship('Case', backref='active_tasks')
    user = db.relationship('User', backref='tasks_initiated')
    
    def __repr__(self):
        return f'<ActiveTask {self.task_type} case:{self.case_id} status:{self.status}>'
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'case_id': self.case_id,
            'task_type': self.task_type,
            'task_id': self.task_id,
            'user_id': self.user_id,
            'status': self.status,
            'progress_percent': self.progress_percent,
            'progress_message': self.progress_message,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'result_data': self.result_data,
            'error_message': self.error_message
        }
