"""Known User Models for CaseScope

Tracks known users discovered across cases with deduplication
and full audit history.
"""
import re
from datetime import datetime
from models.database import db


class KnownUser(db.Model):
    """Known User model for tracking discovered users
    
    Stores normalized username with related tables for
    aliases, emails, and case associations.
    """
    __tablename__ = 'known_users'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Username - Primary identifier (e.g., jsmith, administrator)
    username = db.Column(db.String(255), nullable=True, index=True)
    
    # SID - Windows Security Identifier (e.g., S-1-5-21-xxx-xxx-xxx-1001)
    sid = db.Column(db.String(255), nullable=True, unique=True, index=True)
    
    # Email - Primary email address
    email = db.Column(db.String(255), nullable=True, index=True)
    
    # Artifact count - incremented when artifacts reference this user
    artifacts_with_user = db.Column(db.Integer, nullable=False, default=0)
    
    # Timestamps
    added_on = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    added_by = db.Column(db.String(80), nullable=True)  # Username who added
    last_seen = db.Column(db.DateTime, nullable=True)
    
    # Analyst notes
    notes = db.Column(db.Text, nullable=True)
    
    # Compromised flag
    compromised = db.Column(db.Boolean, nullable=False, default=False)
    
    # Relationships
    aliases = db.relationship('KnownUserAlias', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    emails = db.relationship('KnownUserEmail', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    cases = db.relationship('KnownUserCase', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<KnownUser {self.id}: {self.username or self.sid}>'
    
    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            'id': self.id,
            'username': self.username,
            'sid': self.sid,
            'email': self.email,
            'artifacts_with_user': self.artifacts_with_user,
            'added_on': self.added_on.isoformat() if self.added_on else None,
            'added_by': self.added_by,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'notes': self.notes,
            'compromised': self.compromised,
            'aliases': [alias.alias for alias in self.aliases],
            'emails': [email.email for email in self.emails],
            'case_count': self.cases.count()
        }
    
    @staticmethod
    def normalize_username(username):
        """Normalize a username for matching
        
        - Strip whitespace
        - Convert to uppercase
        - Remove domain prefix (DOMAIN\\user -> user)
        - Remove domain suffix (user@domain.com -> user)
        
        Returns tuple: (normalized_username, domain_if_any)
        """
        if not username:
            return None, None
        
        username = username.strip()
        domain = None
        
        # Handle DOMAIN\user format
        if '\\' in username:
            parts = username.split('\\', 1)
            domain = parts[0].upper()
            username = parts[1]
        
        # Handle user@domain format (extract just the username part)
        if '@' in username and domain is None:
            parts = username.split('@', 1)
            username = parts[0]
            domain = parts[1].upper()
        
        return username.upper(), domain
    
    @staticmethod
    def extract_email_prefix(email):
        """Extract username prefix from email address
        
        john.smith@company.com -> JOHN.SMITH
        """
        if not email or '@' not in email:
            return None
        
        prefix = email.split('@')[0]
        return prefix.strip().upper() if prefix else None
    
    @staticmethod
    def find_by_username_sid_alias_or_email(username=None, sid=None, email=None):
        """Find a user by username, SID, alias, or email prefix
        
        Implements the deduplication workflow:
        1. Check if username exists
        2. Check if SID matches another known user
        3. Check if username exists in aliases
        4. If email, check if prefix matches username or alias
        
        Returns: (KnownUser or None, match_type)
        match_type: 'username', 'sid', 'alias', 'email_prefix_username', 'email_prefix_alias', None
        """
        # 1. Check exact username match
        if username:
            normalized, _ = KnownUser.normalize_username(username)
            if normalized:
                user = KnownUser.query.filter(
                    db.func.upper(KnownUser.username) == normalized
                ).first()
                if user:
                    return user, 'username'
        
        # 2. Check SID match
        if sid:
            sid_upper = sid.strip().upper()
            user = KnownUser.query.filter(
                db.func.upper(KnownUser.sid) == sid_upper
            ).first()
            if user:
                return user, 'sid'
        
        # 3. Check aliases for username match
        if username:
            normalized, _ = KnownUser.normalize_username(username)
            if normalized:
                alias_match = KnownUserAlias.query.filter(
                    db.func.upper(KnownUserAlias.alias) == normalized
                ).first()
                if alias_match:
                    return alias_match.user, 'alias'
        
        # 4. If email, check if prefix matches username or alias
        if email:
            prefix = KnownUser.extract_email_prefix(email)
            if prefix:
                # Check if prefix matches a username
                user = KnownUser.query.filter(
                    db.func.upper(KnownUser.username) == prefix
                ).first()
                if user:
                    return user, 'email_prefix_username'
                
                # Check if prefix matches an alias
                alias_match = KnownUserAlias.query.filter(
                    db.func.upper(KnownUserAlias.alias) == prefix
                ).first()
                if alias_match:
                    return alias_match.user, 'email_prefix_alias'
        
        return None, None
    
    def add_alias(self, alias):
        """Add an alias if not already present
        
        Stores the full alias format (e.g., DOMAIN\\USER) not normalized.
        """
        if not alias:
            return False
        
        alias = alias.strip().upper()
        if not alias or len(alias) < 2:
            return False
        
        # Don't add if it's exactly the same as username (case-insensitive)
        if self.username and alias == self.username.upper():
            return False
        
        # Also check if the normalized form matches (DOMAIN\USER vs USER)
        normalized, _ = KnownUser.normalize_username(alias)
        if normalized and self.username and normalized == self.username.upper():
            # This is DOMAIN\username - it's a valid alias, don't reject it
            # Only reject if the full alias equals the username
            pass
        
        existing = KnownUserAlias.query.filter_by(
            user_id=self.id
        ).filter(db.func.upper(KnownUserAlias.alias) == alias).first()
        
        if not existing:
            new_alias = KnownUserAlias(
                user_id=self.id,
                alias=alias,  # Store full format, not normalized
                first_seen=datetime.utcnow()
            )
            db.session.add(new_alias)
            return True
        return False
    
    def add_email(self, email):
        """Add an email if not already present"""
        if not email or '@' not in email:
            return False
        
        email = email.strip().lower()
        
        # Don't add if it's the same as primary email
        if self.email and email == self.email.lower():
            return False
        
        existing = KnownUserEmail.query.filter_by(
            user_id=self.id
        ).filter(db.func.lower(KnownUserEmail.email) == email).first()
        
        if not existing:
            new_email = KnownUserEmail(
                user_id=self.id,
                email=email,
                first_seen=datetime.utcnow()
            )
            db.session.add(new_email)
            return True
        return False
    
    def link_to_case(self, case_id):
        """Link this user to a case"""
        existing = KnownUserCase.query.filter_by(
            user_id=self.id,
            case_id=case_id
        ).first()
        
        if not existing:
            new_link = KnownUserCase(
                user_id=self.id,
                case_id=case_id,
                first_seen_in_case=datetime.utcnow()
            )
            db.session.add(new_link)
            return True
        return False


class KnownUserAlias(db.Model):
    """Aliases for a known user (alternate usernames, formats, etc.)"""
    __tablename__ = 'known_user_aliases'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('known_users.id'), nullable=False, index=True)
    alias = db.Column(db.String(255), nullable=False, index=True)
    first_seen = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    __table_args__ = (
        db.UniqueConstraint('user_id', 'alias', name='uq_user_alias'),
    )
    
    def __repr__(self):
        return f'<KnownUserAlias {self.alias}>'


class KnownUserEmail(db.Model):
    """Additional email addresses for a known user"""
    __tablename__ = 'known_user_emails'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('known_users.id'), nullable=False, index=True)
    email = db.Column(db.String(255), nullable=False, index=True)
    first_seen = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    __table_args__ = (
        db.UniqueConstraint('user_id', 'email', name='uq_user_email'),
    )
    
    def __repr__(self):
        return f'<KnownUserEmail {self.email}>'


class KnownUserCase(db.Model):
    """Junction table linking users to cases"""
    __tablename__ = 'known_user_cases'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('known_users.id'), nullable=False, index=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=False, index=True)
    first_seen_in_case = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    __table_args__ = (
        db.UniqueConstraint('user_id', 'case_id', name='uq_user_case'),
    )
    
    def __repr__(self):
        return f'<KnownUserCase user={self.user_id} case={self.case_id}>'


class KnownUserAudit(db.Model):
    """Audit log for changes to known users
    
    Tracks all changes except artifacts_with_user counter updates.
    """
    __tablename__ = 'known_users_audit'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('known_users.id'), nullable=False, index=True)
    changed_on = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    changed_by = db.Column(db.String(80), nullable=False)  # Username
    field_name = db.Column(db.String(100), nullable=False)  # Field or table that changed
    action = db.Column(db.String(20), nullable=False)  # create, update, delete
    old_value = db.Column(db.Text, nullable=True)
    new_value = db.Column(db.Text, nullable=True)
    
    def __repr__(self):
        return f'<KnownUserAudit {self.id}: {self.action} {self.field_name}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'changed_on': self.changed_on.isoformat() if self.changed_on else None,
            'changed_by': self.changed_by,
            'field_name': self.field_name,
            'action': self.action,
            'old_value': self.old_value,
            'new_value': self.new_value
        }
    
    @staticmethod
    def log_change(user_id, changed_by, field_name, action, old_value=None, new_value=None):
        """Create an audit log entry"""
        audit = KnownUserAudit(
            user_id=user_id,
            changed_by=changed_by,
            field_name=field_name,
            action=action,
            old_value=str(old_value) if old_value is not None else None,
            new_value=str(new_value) if new_value is not None else None
        )
        db.session.add(audit)
        return audit
