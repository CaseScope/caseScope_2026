"""Unified Forensic Audit Log Model

Immutable audit trail for all system changes.
Captures who, what, when, where for compliance and forensic purposes.

Design principles:
- Append-only (no updates, no deletes)
- Captures before/after state for changes
- Tracks remote IP for accountability
- Unified schema for all entity types
- Denormalizes user info for immutability
"""
from datetime import datetime
import json
from models.database import db
from sqlalchemy import event


class AuditAction:
    """Standardized action types for audit logging"""
    # CRUD operations
    CREATED = 'created'
    UPDATED = 'updated'
    DELETED = 'deleted'
    
    # Entity-specific actions
    LINKED = 'linked'
    UNLINKED = 'unlinked'
    ENRICHED = 'enriched'
    ARCHIVED = 'archived'
    RESTORED = 'restored'
    IMPORTED = 'imported'
    EXPORTED = 'exported'
    
    # File-specific actions
    PREFLIGHT = 'preflight'
    UPLOADED = 'uploaded'
    EXTRACTED = 'extracted'
    QUEUED = 'queued'
    INGESTED = 'ingested'
    REINDEXED = 'reindexed'
    DUPLICATE_SKIPPED = 'duplicate_skipped'
    DUPLICATE_DELETED = 'duplicate_deleted'
    
    # User/Auth actions
    LOGIN = 'login'
    LOGOUT = 'logout'
    LOGIN_FAILED = 'login_failed'
    PASSWORD_CHANGED = 'password_changed'
    LOCKED = 'locked'
    UNLOCKED = 'unlocked'
    
    # Settings
    SETTING_CHANGED = 'setting_changed'
    
    @classmethod
    def all(cls):
        return [
            cls.CREATED, cls.UPDATED, cls.DELETED,
            cls.LINKED, cls.UNLINKED, cls.ENRICHED, cls.ARCHIVED, cls.RESTORED,
            cls.IMPORTED, cls.EXPORTED,
            cls.PREFLIGHT, cls.UPLOADED, cls.EXTRACTED, cls.QUEUED, cls.INGESTED, cls.REINDEXED,
            cls.DUPLICATE_SKIPPED, cls.DUPLICATE_DELETED,
            cls.LOGIN, cls.LOGOUT, cls.LOGIN_FAILED, cls.PASSWORD_CHANGED,
            cls.LOCKED, cls.UNLOCKED,
            cls.SETTING_CHANGED
        ]


class AuditEntityType:
    """Entity types for audit logging"""
    # Cases
    CASE = 'case'
    CASE_FILE = 'case_file'
    CASE_REPORT = 'case_report'
    
    # Case entities
    IOC = 'ioc'
    KNOWN_SYSTEM = 'known_system'
    KNOWN_USER = 'known_user'
    
    # System entities
    SYSTEM_USER = 'system_user'
    SETTING = 'setting'
    NOISE_RULE = 'noise_rule'
    CLIENT = 'client'
    
    # Evidence
    EVIDENCE_FILE = 'evidence_file'
    
    # RAG/AI
    ATTACK_PATTERN = 'attack_pattern'
    
    # Auth
    SESSION = 'session'
    
    @classmethod
    def all(cls):
        return [
            cls.CASE, cls.CASE_FILE, cls.CASE_REPORT,
            cls.IOC, cls.KNOWN_SYSTEM, cls.KNOWN_USER,
            cls.SYSTEM_USER, cls.SETTING, cls.NOISE_RULE, cls.CLIENT,
            cls.EVIDENCE_FILE, cls.ATTACK_PATTERN, cls.SESSION
        ]


class AuditLog(db.Model):
    """
    Immutable forensic audit trail for all system changes.
    
    This table is append-only. Updates and deletes are prevented
    via SQLAlchemy event listeners.
    """
    __tablename__ = 'audit_log'
    
    # Primary key - using BigInteger for high-volume logging
    id = db.Column(db.BigInteger, primary_key=True)
    
    # When - timestamp of the action
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    
    # Who - user information (denormalized for immutability)
    user_id = db.Column(db.Integer, nullable=True)
    username = db.Column(db.String(80), nullable=False, index=True)
    
    # Where - client information
    remote_ip = db.Column(db.String(45), nullable=True)  # IPv4 or IPv6
    user_agent = db.Column(db.String(500), nullable=True)
    
    # What entity was affected
    entity_type = db.Column(db.String(50), nullable=False, index=True)
    entity_id = db.Column(db.String(100), nullable=True, index=True)
    entity_name = db.Column(db.String(255), nullable=True)  # Human-readable, denormalized
    
    # What action was performed
    action = db.Column(db.String(50), nullable=False, index=True)
    
    # What changed (for updates)
    field_name = db.Column(db.String(100), nullable=True)
    old_value = db.Column(db.Text, nullable=True)
    new_value = db.Column(db.Text, nullable=True)
    
    # Context
    case_uuid = db.Column(db.String(36), nullable=True, index=True)
    details = db.Column(db.Text, nullable=True)  # JSON for additional context
    
    # Composite indexes for common queries
    __table_args__ = (
        db.Index('ix_audit_entity_time', 'entity_type', 'entity_id', 'timestamp'),
        db.Index('ix_audit_user_time', 'username', 'timestamp'),
        db.Index('ix_audit_case_time', 'case_uuid', 'timestamp'),
        db.Index('ix_audit_action_time', 'action', 'timestamp'),
    )
    
    def __repr__(self):
        return f'<AuditLog {self.id}: {self.action} {self.entity_type}/{self.entity_id} by {self.username}>'
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Always set timestamp on creation
        if not self.timestamp:
            self.timestamp = datetime.utcnow()
    
    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'user_id': self.user_id,
            'username': self.username,
            'remote_ip': self.remote_ip,
            'user_agent': self.user_agent,
            'entity_type': self.entity_type,
            'entity_id': self.entity_id,
            'entity_name': self.entity_name,
            'action': self.action,
            'field_name': self.field_name,
            'old_value': self.old_value,
            'new_value': self.new_value,
            'case_uuid': self.case_uuid,
            'details': json.loads(self.details) if self.details else None
        }
    
    @classmethod
    def log(cls, entity_type: str, entity_id, action: str,
            username: str = None, user_id: int = None,
            entity_name: str = None, field_name: str = None,
            old_value=None, new_value=None,
            case_uuid: str = None, details: dict = None,
            remote_ip: str = None, user_agent: str = None):
        """
        Create an audit log entry.
        
        Args:
            entity_type: Type of entity (use AuditEntityType constants)
            entity_id: ID or UUID of the entity
            action: Action performed (use AuditAction constants)
            username: Username who performed action (auto-detected if None)
            user_id: User ID (auto-detected if None)
            entity_name: Human-readable name for the entity
            field_name: Specific field that changed (for updates)
            old_value: Previous value (auto-serialized to JSON if complex)
            new_value: New value (auto-serialized to JSON if complex)
            case_uuid: Associated case UUID
            details: Additional context as dict
            remote_ip: Client IP (auto-detected if None)
            user_agent: Client user agent (auto-detected if None)
        
        Returns:
            AuditLog entry (already committed)
        """
        # Auto-detect user info from Flask context
        if username is None:
            try:
                from flask_login import current_user
                if current_user and current_user.is_authenticated:
                    username = current_user.username
                    user_id = current_user.id
                else:
                    username = 'system'
            except RuntimeError:
                # Outside request context (e.g., Celery task)
                username = 'system'
        
        # Auto-detect remote IP
        if remote_ip is None:
            remote_ip = cls._get_remote_ip()
        
        # Auto-detect user agent
        if user_agent is None:
            user_agent = cls._get_user_agent()
        
        # Serialize complex values to JSON
        if old_value is not None and not isinstance(old_value, str):
            old_value = json.dumps(old_value)
        if new_value is not None and not isinstance(new_value, str):
            new_value = json.dumps(new_value)
        if details is not None:
            details = json.dumps(details)
        
        # Convert entity_id to string
        entity_id = str(entity_id) if entity_id is not None else None
        
        entry = cls(
            username=username,
            user_id=user_id,
            remote_ip=remote_ip,
            user_agent=user_agent,
            entity_type=entity_type,
            entity_id=entity_id,
            entity_name=entity_name,
            action=action,
            field_name=field_name,
            old_value=old_value,
            new_value=new_value,
            case_uuid=case_uuid,
            details=details
        )
        
        db.session.add(entry)
        db.session.commit()
        return entry
    
    @classmethod
    def log_changes(cls, entity_type: str, entity_id, action: str,
                    changes: dict, entity_name: str = None,
                    case_uuid: str = None, **kwargs):
        """
        Log multiple field changes for an entity.
        
        Args:
            entity_type: Type of entity
            entity_id: ID of the entity
            action: Action performed
            changes: Dict of {field_name: (old_value, new_value)}
            entity_name: Human-readable name
            case_uuid: Associated case UUID
            **kwargs: Additional args passed to log()
        
        Returns:
            List of AuditLog entries
        """
        entries = []
        for field_name, (old_val, new_val) in changes.items():
            entry = cls.log(
                entity_type=entity_type,
                entity_id=entity_id,
                action=action,
                entity_name=entity_name,
                field_name=field_name,
                old_value=old_val,
                new_value=new_val,
                case_uuid=case_uuid,
                **kwargs
            )
            entries.append(entry)
        return entries
    
    @staticmethod
    def _get_remote_ip() -> str:
        """Get client IP, handling proxies"""
        try:
            from flask import request, has_request_context
            if not has_request_context():
                return None
            
            # Check X-Forwarded-For (behind proxy/load balancer)
            if request.headers.get('X-Forwarded-For'):
                return request.headers.get('X-Forwarded-For').split(',')[0].strip()
            
            # Check X-Real-IP (nginx)
            if request.headers.get('X-Real-IP'):
                return request.headers.get('X-Real-IP')
            
            # Direct connection
            return request.remote_addr
        except Exception:
            return None
    
    @staticmethod
    def _get_user_agent() -> str:
        """Get client user agent"""
        try:
            from flask import request, has_request_context
            if not has_request_context():
                return None
            return request.headers.get('User-Agent', '')[:500]
        except Exception:
            return None
    
    # Query helpers
    @classmethod
    def get_by_entity(cls, entity_type: str, entity_id: str, limit: int = 100):
        """Get audit entries for a specific entity"""
        return cls.query.filter_by(
            entity_type=entity_type,
            entity_id=str(entity_id)
        ).order_by(cls.timestamp.desc()).limit(limit).all()
    
    @classmethod
    def get_by_case(cls, case_uuid: str, limit: int = 100):
        """Get audit entries for a case"""
        return cls.query.filter_by(
            case_uuid=case_uuid
        ).order_by(cls.timestamp.desc()).limit(limit).all()
    
    @classmethod
    def get_by_user(cls, username: str, limit: int = 100):
        """Get audit entries by user"""
        return cls.query.filter_by(
            username=username
        ).order_by(cls.timestamp.desc()).limit(limit).all()
    
    @classmethod
    def get_recent(cls, limit: int = 100, entity_type: str = None, action: str = None):
        """Get recent audit entries with optional filters"""
        query = cls.query
        if entity_type:
            query = query.filter_by(entity_type=entity_type)
        if action:
            query = query.filter_by(action=action)
        return query.order_by(cls.timestamp.desc()).limit(limit).all()
    
    @classmethod
    def search(cls, start_date=None, end_date=None, username=None,
               entity_type=None, action=None, case_uuid=None,
               search_term=None, limit: int = 500):
        """
        Search audit log with multiple filters.
        
        Returns:
            List of AuditLog entries matching criteria
        """
        query = cls.query
        
        if start_date:
            query = query.filter(cls.timestamp >= start_date)
        if end_date:
            query = query.filter(cls.timestamp <= end_date)
        if username:
            query = query.filter(cls.username == username)
        if entity_type:
            query = query.filter(cls.entity_type == entity_type)
        if action:
            query = query.filter(cls.action == action)
        if case_uuid:
            query = query.filter(cls.case_uuid == case_uuid)
        if search_term:
            search_pattern = f'%{search_term}%'
            query = query.filter(
                db.or_(
                    cls.entity_name.ilike(search_pattern),
                    cls.old_value.ilike(search_pattern),
                    cls.new_value.ilike(search_pattern),
                    cls.details.ilike(search_pattern)
                )
            )
        
        return query.order_by(cls.timestamp.desc()).limit(limit).all()


# ============================================================
# Immutability Enforcement
# ============================================================

def _prevent_audit_modification(mapper, connection, target):
    """Prevent updates to audit log entries"""
    raise ValueError("Audit log entries are immutable and cannot be modified")


def _prevent_audit_deletion(mapper, connection, target):
    """Prevent deletion of audit log entries"""
    raise ValueError("Audit log entries are immutable and cannot be deleted")


# Register SQLAlchemy event listeners to enforce immutability
event.listen(AuditLog, 'before_update', _prevent_audit_modification)
event.listen(AuditLog, 'before_delete', _prevent_audit_deletion)


# ============================================================
# Convenience Functions
# ============================================================

def audit_create(entity_type: str, entity_id, entity_name: str = None,
                 case_uuid: str = None, details: dict = None):
    """Log entity creation"""
    return AuditLog.log(
        entity_type=entity_type,
        entity_id=entity_id,
        action=AuditAction.CREATED,
        entity_name=entity_name,
        case_uuid=case_uuid,
        details=details
    )


def audit_update(entity_type: str, entity_id, changes: dict,
                 entity_name: str = None, case_uuid: str = None):
    """
    Log entity update with field changes.
    
    Args:
        changes: Dict of {field_name: (old_value, new_value)}
    """
    return AuditLog.log_changes(
        entity_type=entity_type,
        entity_id=entity_id,
        action=AuditAction.UPDATED,
        changes=changes,
        entity_name=entity_name,
        case_uuid=case_uuid
    )


def audit_delete(entity_type: str, entity_id, entity_name: str = None,
                 case_uuid: str = None, final_state: dict = None):
    """Log entity deletion, optionally capturing final state"""
    return AuditLog.log(
        entity_type=entity_type,
        entity_id=entity_id,
        action=AuditAction.DELETED,
        entity_name=entity_name,
        case_uuid=case_uuid,
        details=final_state
    )


def audit_login(username: str, success: bool, reason: str = None):
    """Log login attempt"""
    action = AuditAction.LOGIN if success else AuditAction.LOGIN_FAILED
    details = {'reason': reason} if reason else None
    
    return AuditLog.log(
        entity_type=AuditEntityType.SESSION,
        entity_id=None,
        action=action,
        username=username,
        entity_name=username,
        details=details
    )


def audit_logout(username: str):
    """Log user logout"""
    return AuditLog.log(
        entity_type=AuditEntityType.SESSION,
        entity_id=None,
        action=AuditAction.LOGOUT,
        username=username,
        entity_name=username
    )


def audit_setting_change(key: str, old_value, new_value):
    """Log setting change"""
    return AuditLog.log(
        entity_type=AuditEntityType.SETTING,
        entity_id=key,
        action=AuditAction.SETTING_CHANGED,
        entity_name=key,
        field_name='value',
        old_value=old_value,
        new_value=new_value
    )
