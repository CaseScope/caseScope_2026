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
    """
    __tablename__ = 'case_file'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False, index=True)
    filename = db.Column(db.String(500), nullable=False)
    original_filename = db.Column(db.String(500))
    file_type = db.Column(db.String(50))  # evtx, json, csv, etc.
    file_size = db.Column(db.BigInteger)  # bytes
    file_path = db.Column(db.String(1000))  # storage path
    
    # Parsed metadata
    source_system = db.Column(db.String(200))  # Computer name from events
    event_count = db.Column(db.Integer, default=0)
    sigma_violations = db.Column(db.Integer, default=0)
    ioc_count = db.Column(db.Integer, default=0)
    
    # Upload tracking
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    # Processing status
    status = db.Column(db.String(50), default='pending')  # pending, processing, indexed, failed
    error_message = db.Column(db.Text)
    indexed_at = db.Column(db.DateTime)
    
    # Visibility flag - hide empty files by default
    is_hidden = db.Column(db.Boolean, default=False)  # True for files with 0 events
    
    # Relationships
    case = db.relationship('Case', backref='files')
    uploader = db.relationship('User', backref='uploaded_files')
    
    def __repr__(self):
        return f'<CaseFile {self.filename}>'


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
    value = db.Column(db.Text, nullable=False, index=True)
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
