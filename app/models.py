#!/usr/bin/env python3
"""
CaseScope 2026 v1.0.0 - Database Models
Minimal, clean schema with only essential fields
"""

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()


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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    last_login = db.Column(db.DateTime)
    
    # Relationships
    creator = db.relationship('User', remote_side=[id], backref='users_created', foreign_keys=[created_by])


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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # EDR Report field (v1.37.0) - Stores the full EDR/MDR report text
    edr_report = db.Column(db.Text)
    
    # VPN IP Ranges field (v1.43.0) - Stores VPN IP ranges for triage identification
    # Format: "192.168.100.1-192.168.100.50, 10.10.0.0/24" (comma or semicolon separated)
    vpn_ip_ranges = db.Column(db.Text)
    
    # Archive fields (v1.18.0)
    archive_path = db.Column(db.String(1000))  # Full path to archive ZIP
    archived_at = db.Column(db.DateTime)  # When archived
    archived_by = db.Column(db.Integer, db.ForeignKey('user.id'))  # Who archived
    restored_at = db.Column(db.DateTime)  # When last restored (audit trail)
    
    # Relationships
    files = db.relationship('CaseFile', back_populates='case', lazy='dynamic')
    creator = db.relationship('User', foreign_keys=[created_by], backref='cases_created')
    assignee = db.relationship('User', foreign_keys=[assigned_to], backref='cases_assigned')
    archiver = db.relationship('User', foreign_keys=[archived_by], backref='cases_archived')


class CaseLock(db.Model):
    """
    Case Lock Management (v1.25.0)
    Tracks which user is actively working on a case to prevent conflicts
    """
    __tablename__ = 'case_lock'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False, unique=True, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    locked_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_activity = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    session_id = db.Column(db.String(255), nullable=False)  # Flask session ID
    
    # Relationships
    case = db.relationship('Case', backref='lock')
    user = db.relationship('User', backref='case_locks')
    
    def is_stale(self, timeout_hours=4):
        """Check if lock is stale (no activity for timeout_hours)"""
        if not self.last_activity:
            return True
        time_since_activity = datetime.utcnow() - self.last_activity
        return time_since_activity.total_seconds() > (timeout_hours * 3600)
    
    def update_activity(self):
        """Update last activity timestamp"""
        self.last_activity = datetime.utcnow()


class CaseFile(db.Model):
    """Files uploaded to cases"""
    __tablename__ = 'case_file'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False, index=True)
    filename = db.Column(db.String(500), nullable=False)
    original_filename = db.Column(db.String(500), nullable=False)
    file_path = db.Column(db.String(1000), nullable=False)
    file_size = db.Column(db.BigInteger, default=0)  # bytes
    size_mb = db.Column(db.Integer, default=0)  # MB rounded
    file_hash = db.Column(db.String(64), index=True)  # SHA256
    file_type = db.Column(db.String(20))  # EVTX, JSON, NDJSON, CSV, ZIP
    mime_type = db.Column(db.String(100))
    
    # Processing status
    indexing_status = db.Column(db.String(50), default='Queued')  # Queued, Indexing, Completed, Failed
    error_message = db.Column(db.Text)  # Detailed error message for failed files
    is_indexed = db.Column(db.Boolean, default=False)
    is_hidden = db.Column(db.Boolean, default=False)  # Hide 0-event files
    is_deleted = db.Column(db.Boolean, default=False)
    
    # Event counts
    event_count = db.Column(db.Integer, default=0)
    estimated_event_count = db.Column(db.Integer, default=0)
    violation_count = db.Column(db.Integer, default=0)
    sigma_event_count = db.Column(db.Integer, default=0)
    ioc_event_count = db.Column(db.Integer, default=0)
    
    # OpenSearch integration
    opensearch_key = db.Column(db.String(200), index=True)
    
    # Task tracking
    celery_task_id = db.Column(db.String(255))
    
    # Metadata
    upload_type = db.Column(db.String(20), default='http')  # http, bulk, staging
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    case = db.relationship('Case', back_populates='files')


class SigmaRule(db.Model):
    """SIGMA detection rules"""
    __tablename__ = 'sigma_rule'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text)
    rule_yaml = db.Column(db.Text, nullable=False)
    level = db.Column(db.String(20))  # low, medium, high, critical
    tags = db.Column(db.Text)  # JSON array
    is_enabled = db.Column(db.Boolean, default=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class SigmaViolation(db.Model):
    """SIGMA detection matches"""
    __tablename__ = 'sigma_violation'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False, index=True)
    file_id = db.Column(db.Integer, db.ForeignKey('case_file.id'), nullable=False, index=True)
    rule_id = db.Column(db.Integer, db.ForeignKey('sigma_rule.id'), nullable=False)
    event_id = db.Column(db.String(64), index=True)
    event_data = db.Column(db.Text)  # JSON
    matched_fields = db.Column(db.Text)  # JSON
    severity = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class IOC(db.Model):
    """Indicators of Compromise"""
    __tablename__ = 'ioc'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False, index=True)
    ioc_type = db.Column(db.String(50), nullable=False)  # ip, username, user_sid, hostname, fqdn, command, command_complex, filename, malware_name, hash, port, url, registry_key, email, pid, other
    ioc_value = db.Column(db.String(500), nullable=False, index=True)
    description = db.Column(db.Text)
    threat_level = db.Column(db.String(20), default='medium')
    is_active = db.Column(db.Boolean, default=True)
    
    # User tracking
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # OpenCTI integration
    opencti_enrichment = db.Column(db.Text)  # JSON: enriched data from OpenCTI
    opencti_enriched_at = db.Column(db.DateTime)
    
    # DFIR-IRIS integration
    dfir_iris_synced = db.Column(db.Boolean, default=False)
    dfir_iris_sync_date = db.Column(db.DateTime)
    dfir_iris_ioc_id = db.Column(db.String(100))  # DFIR-IRIS IOC ID


class IOCMatch(db.Model):
    """IOC detection matches"""
    __tablename__ = 'ioc_match'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False, index=True)
    ioc_id = db.Column(db.Integer, db.ForeignKey('ioc.id'), nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey('case_file.id'), nullable=False)
    index_name = db.Column(db.String(200), index=True)
    event_id = db.Column(db.String(64))
    event_data = db.Column(db.Text)  # JSON
    matched_field = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class System(db.Model):
    """Systems identified in case (servers, workstations, firewalls, etc.)"""
    __tablename__ = 'system'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False, index=True)
    system_name = db.Column(db.String(255), nullable=False, index=True)
    ip_address = db.Column(db.String(45))  # IPv4 (15) or IPv6 (45) address
    system_type = db.Column(db.String(50), nullable=False, default='workstation')  # server, workstation, firewall, switch, printer, actor_system, unknown
    
    # User tracking
    added_by = db.Column(db.String(100), default='CaseScope')  # username or 'CaseScope' for auto-detection
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Visibility control
    hidden = db.Column(db.Boolean, default=False)
    
    # OpenCTI integration
    opencti_enrichment = db.Column(db.Text)  # JSON: enriched data from OpenCTI
    opencti_enriched_at = db.Column(db.DateTime)
    
    # DFIR-IRIS integration
    dfir_iris_synced = db.Column(db.Boolean, default=False)
    dfir_iris_sync_date = db.Column(db.DateTime)
    dfir_iris_asset_id = db.Column(db.String(100))  # DFIR-IRIS Asset ID
    
    # Unique constraint: one system name per case
    __table_args__ = (db.UniqueConstraint('case_id', 'system_name', name='_case_system_uc'),)


class KnownUser(db.Model):
    """Known/Valid users in the environment (not CaseScope application users) - Case-specific"""
    __tablename__ = 'known_user'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False, index=True)
    username = db.Column(db.String(255), nullable=False, index=True)
    user_type = db.Column(db.String(20), nullable=False, default='unknown')  # v1.21.0: 'domain', 'local', 'unknown', 'invalid'
    user_sid = db.Column(db.String(255), nullable=True, index=True)  # v1.21.0: Windows Security Identifier (optional)
    compromised = db.Column(db.Boolean, default=False, nullable=False)
    active = db.Column(db.Boolean, default=True, nullable=False)  # v1.20.0: Track if user is currently active
    
    # Tracking metadata
    added_method = db.Column(db.String(20), nullable=False)  # 'manual' or 'csv'
    added_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # CaseScope user who added it
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    case = db.relationship('Case', backref='known_users')
    creator = db.relationship('User', foreign_keys=[added_by], backref='known_users_added')
    
    # Unique constraint: username must be unique per case
    __table_args__ = (db.UniqueConstraint('case_id', 'username', name='uq_known_user_case_username'),)


class SkippedFile(db.Model):
    """Files skipped during upload (duplicates, 0-events, etc.)"""
    __tablename__ = 'skipped_file'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False, index=True)
    filename = db.Column(db.String(500), nullable=False)
    file_size = db.Column(db.BigInteger)
    file_hash = db.Column(db.String(64))
    skip_reason = db.Column(db.String(100))  # duplicate, zero_events, error
    skip_details = db.Column(db.Text)
    upload_type = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class SystemSettings(db.Model):
    """System-wide settings"""
    __tablename__ = 'system_settings'
    
    id = db.Column(db.Integer, primary_key=True)
    setting_key = db.Column(db.String(100), unique=True, nullable=False)
    setting_value = db.Column(db.Text)
    description = db.Column(db.Text)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class EventDescription(db.Model):
    """Windows Event ID descriptions for friendly display"""
    __tablename__ = 'event_description'
    
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, nullable=False, index=True)
    event_source = db.Column(db.String(100))  # e.g., 'Security', 'System', 'Sysmon', 'Custom'
    title = db.Column(db.String(500))
    description = db.Column(db.Text)  # Enrichment text / additional context
    category = db.Column(db.String(100))
    source_url = db.Column(db.String(500))  # Which site it came from
    is_custom = db.Column(db.Boolean, default=False, index=True)  # User-added custom event (v1.13.7)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))  # Who created custom event (v1.13.7)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Composite unique constraint on event_id + source
    __table_args__ = (
        db.UniqueConstraint('event_id', 'event_source', name='_event_source_uc'),
    )


class SearchHistory(db.Model):
    """Search history and saved searches"""
    __tablename__ = 'search_history'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=True, index=True)
    search_query = db.Column(db.Text, nullable=False)  # JSON string of search parameters
    search_name = db.Column(db.String(200))  # Optional name for saved search
    is_favorite = db.Column(db.Boolean, default=False, index=True)
    filter_type = db.Column(db.String(50))  # 'all', 'sigma', 'ioc', 'sigma_and_ioc', 'tagged'
    date_range = db.Column(db.String(50))  # '24h', '7d', '30d', 'custom'
    custom_date_start = db.Column(db.DateTime)
    custom_date_end = db.Column(db.DateTime)
    column_config = db.Column(db.Text)  # JSON string of column configuration
    result_count = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    last_used = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref='search_history')
    case = db.relationship('Case', backref='search_history')


class TimelineTag(db.Model):
    """Timeline tags for events (DFIR-IRIS integration)"""
    __tablename__ = 'timeline_tag'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event_id = db.Column(db.String(64), nullable=False, index=True)  # OpenSearch document ID
    index_name = db.Column(db.String(200), nullable=False, index=True)
    event_data = db.Column(db.Text)  # JSON snapshot of event when tagged
    tag_color = db.Column(db.String(20), default='blue')  # For visual identification
    notes = db.Column(db.Text)  # User notes about this event
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    case = db.relationship('Case', backref='timeline_tags')
    user = db.relationship('User', backref='timeline_tags')
    
    # Composite unique constraint to prevent duplicate tags
    __table_args__ = (
        db.UniqueConstraint('case_id', 'event_id', 'index_name', name='_timeline_tag_uc'),
    )


class TagExclusion(db.Model):
    """Events excluded from Phase 3 auto-tagging.
    
    When a user manually untags an event and wants to prevent it from
    being re-tagged by Phase 3, an exclusion record is created here.
    """
    __tablename__ = 'tag_exclusion'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False, index=True)
    event_id = db.Column(db.String(150), nullable=False, index=True)  # OpenSearch document ID (can be 100+ chars)
    index_name = db.Column(db.String(200), nullable=False, index=True)
    reason = db.Column(db.String(200))  # Optional: "False positive", "Not relevant", etc.
    excluded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    excluded_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    case = db.relationship('Case', backref='tag_exclusions')
    user = db.relationship('User', backref='tag_exclusions', foreign_keys=[excluded_by])
    
    # Unique constraint: one exclusion per event per case
    __table_args__ = (
        db.UniqueConstraint('case_id', 'event_id', 'index_name', name='_tag_exclusion_uc'),
    )


class EventStatus(db.Model):
    """Unified event status tracking.
    
    Replaces the fragmented system of is_hidden, TimelineTag, and TagExclusion
    with a single status field per event.
    
    Statuses:
    - new: Fresh event, just indexed (default)
    - noise: Flagged by known-good/noise processes, excluded from searches
    - hunted: Tagged by Phase 3 triage as potentially interesting
    - confirmed: Analyst reviewed and confirmed as relevant to investigation
    """
    __tablename__ = 'event_status'
    
    # Valid status values
    STATUS_NEW = 'new'
    STATUS_NOISE = 'noise'
    STATUS_HUNTED = 'hunted'
    STATUS_CONFIRMED = 'confirmed'
    VALID_STATUSES = [STATUS_NEW, STATUS_NOISE, STATUS_HUNTED, STATUS_CONFIRMED]
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False, index=True)
    event_id = db.Column(db.String(150), nullable=False, index=True)  # OpenSearch document _id
    status = db.Column(db.String(20), default=STATUS_NEW, nullable=False, index=True)
    updated_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Null for system actions
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, index=True)
    notes = db.Column(db.Text)  # Optional analyst notes
    
    # Relationships
    case = db.relationship('Case', backref='event_statuses')
    user = db.relationship('User', backref='event_status_updates', foreign_keys=[updated_by])
    
    # Unique constraint: one status per event per case
    __table_args__ = (
        db.UniqueConstraint('case_id', 'event_id', name='_event_status_uc'),
    )
    
    def __repr__(self):
        return f'<EventStatus {self.event_id}: {self.status}>'


class AuditLog(db.Model):
    """Audit trail for user actions"""
    __tablename__ = 'audit_log'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True, index=True)  # Nullable for system actions
    username = db.Column(db.String(80))  # Store username for historical reference
    action = db.Column(db.String(100), nullable=False, index=True)  # e.g., 'login', 'create_case', 'delete_file'
    resource_type = db.Column(db.String(50), index=True)  # e.g., 'case', 'file', 'user', 'ioc'
    resource_id = db.Column(db.Integer)  # ID of the affected resource
    resource_name = db.Column(db.String(500))  # Name/description of the resource
    details = db.Column(db.Text)  # JSON or text details about the action
    ip_address = db.Column(db.String(45))  # IPv4 or IPv6
    user_agent = db.Column(db.String(500))  # Browser/client info
    status = db.Column(db.String(20), default='success')  # success, failed, error
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True, nullable=False)
    
    # Relationships
    user = db.relationship('User', backref='audit_logs', foreign_keys=[user_id])


class AIReport(db.Model):
    """AI-generated DFIR reports"""
    __tablename__ = 'ai_report'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False, index=True)
    generated_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending', index=True)  # pending, generating, completed, failed, cancelled
    model_name = db.Column(db.String(50), default='phi3:14b')  # AI model used
    celery_task_id = db.Column(db.String(255), index=True)  # Celery task ID for cancellation
    report_title = db.Column(db.String(500))
    report_content = db.Column(db.Text)  # Full report in markdown format
    prompt_sent = db.Column(db.Text)  # The full prompt sent to the AI (for debugging)
    raw_response = db.Column(db.Text)  # The raw markdown response from AI before HTML conversion
    validation_results = db.Column(db.Text)  # JSON string of validation results
    generation_time_seconds = db.Column(db.Float)  # How long it took to generate
    estimated_duration_seconds = db.Column(db.Float)  # Estimated time based on IOC/event counts
    tokens_per_second = db.Column(db.Float)  # Generation speed (tokens/second)
    total_tokens = db.Column(db.Integer)  # Total tokens generated
    error_message = db.Column(db.Text)  # Error details if failed
    progress_percent = db.Column(db.Integer, default=0)  # 0-100 progress indicator
    progress_message = db.Column(db.String(200))  # Current step description
    current_stage = db.Column(db.String(50))  # Current generation stage
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    completed_at = db.Column(db.DateTime)
    
    # Relationships
    case = db.relationship('Case', backref='ai_reports', foreign_keys=[case_id])
    generator = db.relationship('User', backref='generated_reports', foreign_keys=[generated_by])
    chat_messages = db.relationship('AIReportChat', back_populates='report', lazy='dynamic', cascade='all, delete-orphan')


class AIReportChat(db.Model):
    """Interactive chat messages for AI report refinement"""
    __tablename__ = 'ai_report_chat'
    
    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.Integer, db.ForeignKey('ai_report.id'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'user' or 'assistant'
    message = db.Column(db.Text, nullable=False)  # The chat message content
    applied = db.Column(db.Boolean, default=False)  # Whether AI's suggestion was applied to report
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    report = db.relationship('AIReport', back_populates='chat_messages')
    user = db.relationship('User', backref='ai_chat_messages', foreign_keys=[user_id])


class EvidenceFile(db.Model):
    """Evidence files - archival storage (NOT processed/indexed)"""
    __tablename__ = 'evidence_file'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False, index=True)
    filename = db.Column(db.String(500), nullable=False)
    original_filename = db.Column(db.String(500), nullable=False)
    file_path = db.Column(db.String(1000), nullable=False)
    file_size = db.Column(db.BigInteger, default=0)  # bytes
    size_mb = db.Column(db.Integer, default=0)  # MB rounded
    file_hash = db.Column(db.String(64), index=True)  # SHA256
    file_type = db.Column(db.String(50))  # Detected extension (png, jpg, pdf, docx, xlsx, zip, etc.)
    mime_type = db.Column(db.String(100))
    description = db.Column(db.Text)  # User-provided description of evidence
    
    # Upload metadata
    upload_source = db.Column(db.String(20), default='http')  # http, bulk
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # DFIR-IRIS integration
    dfir_iris_synced = db.Column(db.Boolean, default=False)
    dfir_iris_file_id = db.Column(db.String(100))  # DFIR-IRIS datastore file ID
    dfir_iris_sync_date = db.Column(db.DateTime)
    
    # Relationships
    case = db.relationship('Case', backref='evidence_files')
    uploader = db.relationship('User', foreign_keys=[uploaded_by])


class CaseTimeline(db.Model):
    """AI-generated case timelines for chronological analysis"""
    __tablename__ = 'case_timeline'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False, index=True)
    generated_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending', index=True)  # pending, generating, completed, failed, cancelled
    model_name = db.Column(db.String(50), default='dfir-qwen:latest')  # AI model used (Qwen for timelines)
    celery_task_id = db.Column(db.String(255), index=True)  # Celery task ID for cancellation
    timeline_title = db.Column(db.String(500))
    timeline_content = db.Column(db.Text)  # Full timeline in markdown format
    timeline_json = db.Column(db.Text)  # Structured timeline data (JSON) for programmatic access
    prompt_sent = db.Column(db.Text)  # The full prompt sent to the AI (for debugging)
    raw_response = db.Column(db.Text)  # The raw markdown response from AI
    generation_time_seconds = db.Column(db.Float)  # How long it took to generate
    version = db.Column(db.Integer, default=1)  # Version number (increments on regenerate)
    
    # Event/IOC/System counts at time of generation (for reference)
    event_count = db.Column(db.Integer)
    ioc_count = db.Column(db.Integer)
    system_count = db.Column(db.Integer)
    
    # Progress tracking (for real-time UI updates during generation)
    progress_percent = db.Column(db.Integer, default=0)
    progress_message = db.Column(db.String(500))
    error_message = db.Column(db.Text)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    case = db.relationship('Case', backref='timelines')
    user = db.relationship('User', backref='timelines_generated', foreign_keys=[generated_by])


class AIModel(db.Model):
    """AI model metadata and training status"""
    __tablename__ = 'ai_model'
    
    id = db.Column(db.Integer, primary_key=True)
    model_name = db.Column(db.String(100), unique=True, nullable=False, index=True)  # 'dfir-llama:latest'
    display_name = db.Column(db.String(200), nullable=False)  # 'DFIR-Llama 3.1 8B (Forensic Profile)'
    description = db.Column(db.Text)  # Model description
    speed = db.Column(db.String(50))  # 'Fast', 'Moderate', 'Slow'
    quality = db.Column(db.String(50))  # 'Excellent', 'Good', etc.
    size = db.Column(db.String(50))  # '4.9 GB'
    speed_estimate = db.Column(db.String(200))  # '~25-35 tok/s GPU'
    time_estimate = db.Column(db.String(200))  # '3-5 minutes (GPU)'
    recommended = db.Column(db.Boolean, default=False)  # Is this a recommended model?
    trainable = db.Column(db.Boolean, default=False)  # Can this model be trained with LoRA?
    trained = db.Column(db.Boolean, default=False)  # Has this model been trained?
    trained_date = db.Column(db.DateTime)  # When was it trained?
    training_examples = db.Column(db.Integer)  # How many reports used for training?
    trained_model_path = db.Column(db.String(500))  # Path to LoRA adapter weights
    base_model = db.Column(db.String(100))  # Unsloth base model name (e.g., 'unsloth/qwen2-7b-instruct-bnb-4bit')
    installed = db.Column(db.Boolean, default=False)  # Is model pulled via Ollama?
    cpu_optimal = db.Column(db.JSON)  # CPU-optimized parameters (JSON)
    gpu_optimal = db.Column(db.JSON)  # GPU-optimized parameters (JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AITrainingSession(db.Model):
    """Persistent tracking of AI training sessions for UI progress monitoring"""
    __tablename__ = 'ai_training_session'
    
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.String(100), unique=True, nullable=False, index=True)  # Celery task ID
    model_name = db.Column(db.String(100), nullable=False)  # Model being trained
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Who started it
    status = db.Column(db.String(20), default='pending', index=True)  # pending, running, completed, failed
    progress = db.Column(db.Integer, default=0)  # 0-100
    current_step = db.Column(db.String(200))  # 'Step 3/5: Training LoRA adapter...'
    log = db.Column(db.Text)  # Full training log
    error_message = db.Column(db.Text)  # Error details if failed
    report_count = db.Column(db.Integer)  # Number of reports used for training
    started_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)  # Actual training start time
    completed_at = db.Column(db.DateTime)  # When training finished
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship
    user = db.relationship('User', backref='training_sessions')


class SystemToolsSetting(db.Model):
    """
    Known-good tools and IPs to exclude from hunting/tagging.
    
    Allows administrators to define:
    - RMM tools (LabTech, Datto, etc.) - events spawned by these are excluded
    - Remote tools with known-good IDs (ScreenConnect sessions, TeamViewer IDs)
    - EDR/Security tools (Huntress, SentinelOne, etc.) - exclude routine, keep responses
    - Known-good IP ranges (internal networks, analyst IPs)
    
    Added in v1.38.0, EDR tools added in v1.40.0
    """
    __tablename__ = 'system_tools_setting'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Type of setting: 'rmm_tool', 'remote_tool', 'edr_tool', 'known_good_ip'
    setting_type = db.Column(db.String(50), nullable=False, index=True)
    
    # For RMM, Remote, and EDR tools
    tool_name = db.Column(db.String(100))  # 'ConnectWise Automate', 'ScreenConnect', 'Huntress', etc.
    executable_pattern = db.Column(db.String(500))  # 'LTSVC.exe,LTSvcMon.exe' or 'HuntressAgent.exe'
    
    # For Remote tools with session IDs (e.g., ScreenConnect)
    known_good_ids = db.Column(db.Text)  # JSON list: ["id1", "id2"]
    
    # For IP exclusions
    ip_or_cidr = db.Column(db.String(50))  # '192.168.1.0/24' or '10.0.0.50'
    
    # For EDR tools (v1.40.0) - control what to exclude vs keep
    exclude_routine = db.Column(db.Boolean, default=True)  # Exclude routine health checks
    keep_responses = db.Column(db.Boolean, default=True)   # Keep isolation/response actions
    routine_commands = db.Column(db.Text)  # JSON list: ["whoami", "systeminfo", "ipconfig"]
    response_patterns = db.Column(db.Text)  # JSON list: ["isolat", "quarantin", "block"]
    
    # Description for documentation
    description = db.Column(db.String(500))
    
    # Metadata
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True, index=True)
    
    # Relationship
    creator = db.relationship('User', backref='system_tools_settings')
    
    def __repr__(self):
        return f'<SystemToolsSetting {self.setting_type}: {self.tool_name or self.ip_or_cidr}>'


class AITriageSearch(db.Model):
    """
    AI Triage Search results - automated attack chain analysis.
    
    Stores the results of the 9-phase AI Triage Search:
    1. IOC Extraction from report
    2. IOC Classification (SPECIFIC vs BROAD)
    3. Snowball Hunting (discover new IOCs)
    4. Malware/Recon Hunting
    5. SPECIFIC IOC Search (auto-tag candidates)
    6. BROAD IOC Aggregation (discovery only)
    7. Time Window Analysis (±5 min around anchors)
    8. Process Tree Building
    9. MITRE Pattern Matching + Timeline Auto-Tagging
    
    Added in v1.39.0
    """
    __tablename__ = 'ai_triage_search'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False, index=True)
    generated_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Task tracking
    status = db.Column(db.String(20), default='pending', index=True)  # pending, running, completed, failed
    celery_task_id = db.Column(db.String(255), index=True)
    
    # Entry point used
    entry_point = db.Column(db.String(50))  # 'full_triage', 'ioc_hunt', 'tag_hunt'
    search_date = db.Column(db.DateTime)  # Date used for IOC-based hunt
    
    # Results (JSON)
    iocs_extracted_json = db.Column(db.Text)  # IOCs from report
    iocs_discovered_json = db.Column(db.Text)  # IOCs discovered via hunting
    timeline_json = db.Column(db.Text)  # Attack timeline events
    process_trees_json = db.Column(db.Text)  # Process tree structures
    mitre_techniques_json = db.Column(db.Text)  # MITRE techniques found
    summary_json = db.Column(db.Text)  # Full summary for display
    
    # Counts for quick display
    iocs_extracted_count = db.Column(db.Integer, default=0)
    iocs_discovered_count = db.Column(db.Integer, default=0)
    events_analyzed_count = db.Column(db.Integer, default=0)
    timeline_events_count = db.Column(db.Integer, default=0)
    auto_tagged_count = db.Column(db.Integer, default=0)
    techniques_found_count = db.Column(db.Integer, default=0)
    process_trees_count = db.Column(db.Integer, default=0)
    
    # Progress tracking
    current_phase = db.Column(db.Integer, default=0)  # 1-9
    current_phase_name = db.Column(db.String(100))
    progress_message = db.Column(db.String(500))
    progress_percent = db.Column(db.Integer, default=0)
    
    # Timing
    generation_time_seconds = db.Column(db.Float)
    error_message = db.Column(db.Text)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    completed_at = db.Column(db.DateTime)
    
    # Relationships
    case = db.relationship('Case', backref='ai_triage_searches')
    user = db.relationship('User', backref='triage_searches_generated', foreign_keys=[generated_by])
    
    def __repr__(self):
        return f'<AITriageSearch {self.id} case={self.case_id} status={self.status}>'

