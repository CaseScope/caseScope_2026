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
